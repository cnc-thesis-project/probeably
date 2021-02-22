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

executable('probeably',
           'module-geoip.c',
           'database.c',
           'module-http.c',
           'ini.c',
           'main.c',
           'module.c',
           'module-tls.c',
           'module-ssh.c',
           'log.c',
           'config.c',
           'socket.c',
           install : true,
           dependencies : [curl_dep, hiredis_dep, sqlite3_dep, thread_dep, m_dep, ev_dep, wolfssl_dep, zlib_dep],
           include_directories : inc)
