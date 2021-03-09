project('probeably', 'c',
	version : '0.1',
	default_options : ['warning_level=3'])

curl_dep = dependency('libcurl')
hiredis_dep = dependency('hiredis')
sqlite3_dep = dependency('sqlite3')
thread_dep = dependency('threads')
zlib_dep = dependency('zlib')
cc = meson.get_compiler('c')
m_dep = cc.find_library('m', required : false)
ev_dep = cc.find_library('ev')
wolfssl_dep = dependency('wolfssl')

inc = include_directories('include')

log_level = get_option('log_level')

install_data('config.ini')
install_data('probeablyctl',
	install_dir: get_option('bindir'),
	install_mode: 'rwxr-xr-x',
)
install_data('jarm_server',
	install_dir: get_option('bindir'),
	install_mode: 'rwxr-xr-x',
)

executable('probeably',
	'module-geoip.c',
	'module-rdns.c',
	'database.c',
	'module-http.c',
	'module-telnet.c',
	'ini.c',
	'main.c',
	'ipc.c',
	'module.c',
	'module-tls.c',
	'module-ssh.c',
	'log.c',
	'config.c',
	'socket.c',
	'util.c',
	install : true,
	c_args : [
		'-DPRB_LOG_LEVEL=' + log_level.to_string(),
		'-DPRB_CONFIG_DIR="' + join_paths(get_option('prefix'), get_option('sysconfdir')) + '/probeably"',
		'-DPRB_VERSION="' + meson.project_version() + '"',
	],
	dependencies : [
		curl_dep,
		hiredis_dep,
		sqlite3_dep,
		thread_dep,
		m_dep,
		ev_dep,
		wolfssl_dep,
		zlib_dep
	],
	include_directories : inc
)
