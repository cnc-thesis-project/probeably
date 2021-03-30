#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <libssh/libssh.h>
#include "module.h"
#include "module-ssh.h"
#include "socket.h"
#include "database.h"
#include "probeably.h"
#include "config.h"

#define SSH_BUFFER_SIZE (16*1024)
#define SSH_BANNER "SSH-2.0-OpenSSH_7.9 FreeBSD-20200214\r\n"

static char probe_buffer[SSH_BUFFER_SIZE];

static int has_rsa = 0;
static int has_ecdsa = 0;
static int has_ed25519 = 0;

static int ssh_module_check(const char *response, int len)
{
	(void) len;
	if (strncmp(response, "SSH-", 4))
		return -1;
	return 0;
}

// Connect to SSH server and return server string in 'server_string' of size 'size'.
static int _ssh_connect(struct prb_request *r, struct prb_socket *s, char *server_string, size_t size)
{
	int read_len = 0;

	if (prb_socket_connect(s, r->ip, r->port) < 0) {
		return -1;
	}

	prb_socket_write(s, SSH_BANNER, strlen(SSH_BANNER));
	read_len = prb_socket_read(s, server_string, size);

	if (ssh_module_check(server_string, read_len)) {
		PRB_ERROR("ssh", "Not an SSH protocol");
		prb_socket_shutdown(s);
		return -1;
	}

	return read_len;
}

static int ssh_module_test(struct probeably *p, struct prb_request *r,
		struct prb_socket *s, char *response, size_t size)
{
	(void) p;

	PRB_DEBUG("ssh", "SSH test probe");
	return _ssh_connect(r, s, response, size);
}

static void ssh_module_init(struct probeably *p)
{
	p->ports_to_modules[22] = &module_ssh;
	p->ports_to_modules[2222] = &module_ssh;
}

static void ssh_module_cleanup(struct probeably *p)
{
	(void) p;
}

static void ssh_get_public_key(struct probeably *p, struct prb_request *r, const char *key_type)
{
	// retrieve the specified key type of public key
	// done with libssh, since handling diffie hellman shit manually is cancer

	ssh_session ssh_session = ssh_new();
	ssh_options_set(ssh_session, SSH_OPTIONS_HOST, r->ip);
	ssh_options_set(ssh_session, SSH_OPTIONS_PORT, &r->port);
	ssh_options_set(ssh_session, SSH_OPTIONS_TIMEOUT, &prb_config.read_timeout);
	if (!strcmp(key_type, "ssh-ecdsa"))
		ssh_options_set(ssh_session, SSH_OPTIONS_HOSTKEYS, "ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,ecdsa-sha2-nistp256");
	else
		ssh_options_set(ssh_session, SSH_OPTIONS_HOSTKEYS, key_type);

	int rc = ssh_connect(ssh_session);
	if (rc != SSH_OK) {
		ssh_free(ssh_session);
		return;
	}

	ssh_key srv_pubkey = 0;
	rc = ssh_get_server_publickey(ssh_session, &srv_pubkey);
	if (rc < 0) {
		PRB_ERROR("ssh", "Failed to get server public key of type '%s'", key_type);
		ssh_free(ssh_session);
		return;
	}

	char *b64_pubkey = 0;
	const char *key_name = ssh_key_type_to_char(ssh_key_type(srv_pubkey));
	ssh_pki_export_pubkey_base64(srv_pubkey, &b64_pubkey);

	snprintf(probe_buffer, sizeof(probe_buffer), "%s %s", key_name, b64_pubkey);

	PRB_DEBUG("ssh", "Server public key: %s", probe_buffer);

	prb_write_data(p, r, "ssh", key_type, probe_buffer, strlen(probe_buffer), PRB_DB_SUCCESS);

	free(b64_pubkey);
    ssh_key_free(srv_pubkey);

	ssh_disconnect(ssh_session);
	ssh_free(ssh_session);

}

static void ssh_probe(struct probeably *p, struct prb_request *r, struct prb_socket *s)
{
	// get the server banner and cipher list
	// done manually with raw socket, since libssh sucks and cannot give the complete cipher list

	int read_len = _ssh_connect(r, s, probe_buffer, sizeof(probe_buffer));
	if (read_len <= 0)
		return;

	int packet_len = read_len;
	int string_len = 0;

	// ssh packet ends with at least 4 null bytes, if not it hasn't got the whole packet yet
	while (packet_len < 4 || memcmp(&probe_buffer[packet_len-4], "\x00\x00\x00", 4)) {
		read_len = prb_socket_read(s, probe_buffer + packet_len, SSH_BUFFER_SIZE - packet_len);
		if (read_len <= 0)
			break;
		packet_len += read_len;
	}

	// Should always be 2 because of CR LF, but some servers do not comply.
	int crlf_len = 2;

	for (int i = 0; i < packet_len; i++) {
		if (probe_buffer[i] == '\r' || probe_buffer[i] == '\n') {
			if (probe_buffer[i] == '\n') {
				PRB_DEBUG("ssh", "Non-compliant server...");
				crlf_len = 1;
			}
			string_len = i;
			probe_buffer[i] = '\0';
			break;
		}
	}

	PRB_DEBUG("ssh", "Server string is '%s' of length %d", probe_buffer, string_len);

	prb_write_data(p, r, "ssh", "string", probe_buffer, string_len, PRB_DB_SUCCESS);

	// Check if we need to read again to get the ciphers list
	char *ciphers = 0;
	int ciphers_len = 0;

	PRB_DEBUG("ssh", "Reading ciphers");
	ciphers = &probe_buffer[string_len + crlf_len];
	ciphers_len = packet_len - string_len - crlf_len;

	prb_write_data(p, r, "ssh", "ciphers", ciphers, ciphers_len, PRB_DB_SUCCESS);

	if (memmem(ciphers, ciphers_len, "ssh-rsa", strlen("ssh-rsa")))
		has_rsa = 1;
	if (memmem(ciphers, ciphers_len, "ecdsa-sha2-nistp", strlen("ecdsa-sha2-nistp")))
		has_ecdsa = 1;
	if (memmem(ciphers, ciphers_len, "ssh-ed25519", strlen("ssh-ed25519")))
		has_ed25519 = 1;

	prb_socket_shutdown(s);
}

static int ssh_module_run(struct probeably *p, struct prb_request *r, struct prb_socket *s)
{
	has_rsa = 0;
	has_ecdsa = 0;
	has_ed25519 = 0;

	ssh_probe(p, r, s);

	if (has_rsa)
		ssh_get_public_key(p, r, "ssh-rsa");
	if (has_ecdsa)
		ssh_get_public_key(p, r, "ssh-ecdsa");
	if (has_ed25519)
		ssh_get_public_key(p, r, "ssh-ed25519");

	return 0;
}

struct prb_module module_ssh = {
	.flags = PRB_MODULE_REQUIRES_RAW_SOCKET
		| PRB_MODULE_IS_APP_LAYER
		| PRB_MODULE_REQUIRES_TEST_RESPONSE,
	.name = "ssh",
	.init = ssh_module_init,
	.cleanup = ssh_module_cleanup,
	.run = ssh_module_run,
	.check = ssh_module_check,
	.test = ssh_module_test,
};
