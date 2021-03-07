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

executable('probeably',
           'module-geoip.c',
           'module-rdns.c',
           'database.c',
           'module-http.c',
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
               '-DPRB_VERSION="' + meson.project_version() + '"',
           ],
           dependencies : [curl_dep, hiredis_dep, sqlite3_dep, thread_dep, m_dep, ev_dep, wolfssl_dep, zlib_dep],
           include_directories : inc)
