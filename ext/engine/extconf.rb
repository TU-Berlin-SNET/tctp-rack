require 'mkmf'

$defs.push '-Wno-deprecated-declarations'
$libs += ' -lssl -lcrypto '

create_makefile('rack/tctp/engine')
