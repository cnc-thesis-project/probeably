#include <stdio.h>
#include <string.h>
#include "module.h"
#include "module-ssh.h"
#include "socket.h"
#include "database.h"
#include "probeably.h"

#define SSH_BUFFER_SIZE (16*1024)
static char ssh_buffer[SSH_BUFFER_SIZE];

#define SSH_BANNER "SSH-2.0-OpenSSH_7.9 FreeBSD-20200214\r\n"

static const char cipher_exchange_ecdsa[] =
	// packet length
	"\x00\x00\x04\x54"
	// ssh padding length
	"\x09"
	// key exchange init message
	"\x14"
	// cookie (what?)
	"\x82\x22\x65\xcd\x54\x16\x6f\x62\x7b\xef\x2f\x8a\xb8\xbf\xcc\x08"
	// kex algorithms length
	"\x00\x00\x01\x25"
	// kex alggoriths string
	"curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1"
	// server host key algorithm length
	"\x00\x00\x00\x3b"
	// server host key algorithm string
	"ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521"
	// encryption algorithms client to server length
	"\x00\x00\x00\x6c"
	// encryption algorithms client to server string
	"chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com"
	// encryption algorithms server to client length
	"\x00\x00\x00\x6c"
	// encryption algorithms server to client string
	"chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com"
	// mac algorithms client to server length
	"\x00\x00\x00\xd5"
	// mac algorithms client to server string
	"umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1"
	// mac algorithms server to client length
	"\x00\x00\x00\xd5"
	// mac algorithms server to client string
	"umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1"
	// compression algorithms client to server length
	"\x00\x00\x00\x15"
	// compression algorithms client to server string
	"none,zlib@openssh.com"
	// compression algorithms server to client length
	"\x00\x00\x00\x15"
	// compression algorithms server to client string
	"none,zlib@openssh.com"
	// languages client to server length
	"\x00\x00\x00\x00"
	// languages client to server string (empty)
	""
	// languages server to client length
	"\x00\x00\x00\x00"
	// languages server to client string (empty)
	""
	// first kex packet follows
	"\x00"
	// reserved
	"\x00\x00\x00\x00"
	// ssh padding
	"\x00\x00\x00\x00\x00\x00\x00\x00"; // intentionally one null characeter less

static const char cipher_exchange_rsa[] =
	// packet length
	"\x00\x00\x04\x1c"
	// ssh padding length
	"\x05"
	// key exchange init message
	"\x14"
	// cookie (what?)
	"\x82\x22\x65\xcd\x54\x16\x6f\x62\x7b\xef\x2f\x8a\xb8\xbf\xcc\x08"
	// kex algorithms length
	"\x00\x00\x01\x25"
	// kex alggoriths string
	"curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1"
	// server host key algorithm length
	"\x00\x00\x00\x07"
	// server host key algorithm string
	"ssh-rsa"
	// encryption algorithms client to server length
	"\x00\x00\x00\x6c"
	// encryption algorithms client to server string
	"chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com"
	// encryption algorithms server to client length
	"\x00\x00\x00\x6c"
	// encryption algorithms server to client string
	"chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com"
	// mac algorithms client to server length
	"\x00\x00\x00\xd5"
	// mac algorithms client to server string
	"umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1"
	// mac algorithms server to client length
	"\x00\x00\x00\xd5"
	// mac algorithms server to client string
	"umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1"
	// compression algorithms client to server length
	"\x00\x00\x00\x15"
	// compression algorithms client to server string
	"none,zlib@openssh.com"
	// compression algorithms server to client length
	"\x00\x00\x00\x15"
	// compression algorithms server to client string
	"none,zlib@openssh.com"
	// languages client to server length
	"\x00\x00\x00\x00"
	// languages client to server string (empty)
	""
	// languages server to client length
	"\x00\x00\x00\x00"
	// languages server to client string (empty)
	""
	// first kex packet follows
	"\x00"
	// reserved
	"\x00\x00\x00\x00"
	// ssh padding
	"\x00\x00\x00\x00"; // intentionally one null characeter less

static const char cipher_exchange_ed25519[] =
	// packet length
	"\x00\x00\x04\x24"
	// ssh padding length
	"\x09"
	// key exchange init message
	"\x14"
	// cookie (what?)
	"\x82\x22\x65\xcd\x54\x16\x6f\x62\x7b\xef\x2f\x8a\xb8\xbf\xcc\x08"
	// kex algorithms length
	"\x00\x00\x01\x25"
	// kex alggoriths string
	"curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1"
	// server host key algorithm length
	"\x00\x00\x00\x0b"
	// server host key algorithm string
	"ssh-ed25519"
	// encryption algorithms client to server length
	"\x00\x00\x00\x6c"
	// encryption algorithms client to server string
	"chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com"
	// encryption algorithms server to client length
	"\x00\x00\x00\x6c"
	// encryption algorithms server to client string
	"chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com"
	// mac algorithms client to server length
	"\x00\x00\x00\xd5"
	// mac algorithms client to server string
	"umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1"
	// mac algorithms server to client length
	"\x00\x00\x00\xd5"
	// mac algorithms server to client string
	"umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1"
	// compression algorithms client to server length
	"\x00\x00\x00\x15"
	// compression algorithms client to server string
	"none,zlib@openssh.com"
	// compression algorithms server to client length
	"\x00\x00\x00\x15"
	// compression algorithms server to client string
	"none,zlib@openssh.com"
	// languages client to server length
	"\x00\x00\x00\x00"
	// languages client to server string (empty)
	""
	// languages server to client length
	"\x00\x00\x00\x00"
	// languages server to client string (empty)
	""
	// first kex packet follows
	"\x00"
	// reserved
	"\x00\x00\x00\x00"
	// ssh padding
	"\x00\x00\x00\x00\x00\x00\x00\x00"; // intentionally one null characeter less

static const char key_exchange[48] =
	// ssh packet length
	"\x00\x00\x00\x2c"
	// ssh padding length
	"\x06"
	// key exchange method something
	"\x1e"
	// size of something (random number?)
	"\x00\x00\x00\x20"
	// 32 bytes random number? (made in /dev/random)
	"\x8e\xd4\xc3\x70\xe6\x97\x61\x78\x8b\xfe\xcf\x7f\xa3\xf2\xe4\x54"
	"\xd7\x7a\xaf\x3b\x87\x22\x92\x66\xd6\xc4\x6a\xe2\xca\x5a\x77\x81"
	// padding
	"\x00\x00\x00\x00\x00\x00";

static int ssh_module_check(const char *response, int len)
{
	(void) len;
	if (strncmp(response, "SSH-", 4))
		return -1;
	return 0;
}

// Connect to SSH server and return server string in 'server_string' of size 'size'.
static int ssh_connect(struct prb_request *r, struct prb_socket *s, char *server_string, size_t size)
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
	return ssh_connect(r, s, response, size);
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

static void ssh_probe(struct probeably *p, struct prb_request *r, struct prb_socket *s,
		const char *kex_probe, size_t kex_probe_size, const char *key_type)
{
	int read_len = ssh_connect(r, s, ssh_buffer, sizeof(ssh_buffer));
	int string_len = 0;

	// Should always be 2 because of CR LF, but some servers do not comply.
	int crlf_len = 2;

	for (int i = 0; i < read_len; i++) {
		if (ssh_buffer[i] == '\r' || ssh_buffer[i] == '\n') {
			if (ssh_buffer[i] == '\n') {
				PRB_DEBUG("ssh", "Non-compliant server...");
				crlf_len = 1;
			}
			string_len = i;
			ssh_buffer[i] = '\0';
			break;
		}
	}

	PRB_DEBUG("ssh", "Server string is '%s' of length %d", ssh_buffer, string_len);

	if (!strcmp(key_type, "ssh-rsa")) // store server string only once, what the key type is doesn't matter
		prb_write_data(p, r, "ssh", "string", ssh_buffer, string_len, PRB_DB_SUCCESS);

	// Check if we need to read again to get the ciphers list
	char *ciphers;
	int ciphers_len;
	if (string_len + crlf_len == read_len) {
		PRB_DEBUG("ssh", "Reading ciphers");
		read_len = prb_socket_read(s, ssh_buffer, SSH_BUFFER_SIZE);
		ciphers = ssh_buffer;
		ciphers_len = read_len;
	} else {
		ciphers = &ssh_buffer[string_len + crlf_len];
		ciphers_len = read_len - string_len - crlf_len;
		PRB_DEBUG("ssh", "Ciphers packet of size %d already received, presumably...", ciphers_len);
	}

	if (!strcmp(key_type, "ssh-rsa")) // store cipher list only once, what the key type is doesn't matter
		prb_write_data(p, r, "ssh", "ciphers", ciphers, ciphers_len, PRB_DB_SUCCESS);

	// resend servers cipher list
	prb_socket_write(s, kex_probe, kex_probe_size);

	// key exchange, pretty useless but necessary to get public key from the server
	prb_socket_write(s, key_exchange, sizeof(key_exchange));
	read_len = prb_socket_read(s, ssh_buffer, SSH_BUFFER_SIZE);
	prb_socket_shutdown(s);

	prb_write_data(p, r, "ssh", key_type, ssh_buffer, read_len, PRB_DB_SUCCESS);
}

static int ssh_module_run(struct probeably *p, struct prb_request *r, struct prb_socket *s)
{
	ssh_probe(p, r, s, cipher_exchange_rsa, sizeof(cipher_exchange_rsa), "ssh-rsa");
	ssh_probe(p, r, s, cipher_exchange_ecdsa, sizeof(cipher_exchange_ecdsa), "ssh-ecdsa");
	ssh_probe(p, r, s, cipher_exchange_ed25519, sizeof(cipher_exchange_ed25519), "ssh-ed25519");

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
