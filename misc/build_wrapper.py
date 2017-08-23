#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import sys
import argparse

def get_prequel():
    prequel = ('/* Usage:\n'
               ' * gcc -shared -fPIC logger.c -o logger.so -ldl\n'
               ' * LD_PRELOAD=./logger.so test\n'
               ' */\n\n'
               '#define _GNU_SOURCE\n'
               '#include <dlfcn.h>\n'
               '#include "pkcs11_unix.h"\n')
    return prequel

def get_function(name, raw_parameters):
    parameters = re.findall('^\s+(CK_.*?)\s+(.*?)[),\s]', raw_parameters, flags=re.MULTILINE)
    typedef = 'typedef CK_RV (*orig_{name}_f_type)({type_params});\n'.format(
        name=name,
        type_params=', '.join(t + ' ' + p for t, p in parameters)
    )
    definition = (
        'CK_RV {name}({type_params}) {{\n'
        '\torig_{name}_f_type orig_{name};\n'
        '\torig_{name} = (orig_{name}_f_type)dlsym(RTLD_NEXT, "{name}");\n'
        '\treturn orig_{name}({params});\n'
        '}}\n').format(
        name=name,
        type_params=', '.join(t + ' ' + p for t, p in parameters),
        params=', '.join(p for _, p in parameters)
    )

    return typedef, definition

def main():
    # parse command line options
    parser = argparse.ArgumentParser(description='Create an empty PKCS#11 wrapper')
    parser.add_argument('infile', nargs='?', type=argparse.FileType('r'), default=sys.stdin,
        help='Header file listing all the PKCS#11 function declarations, typically pkcs11f.h')
    parser.add_argument('-o', dest='outfile', type=argparse.FileType('w'), default=sys.stdout,
        help='Pathname of the empty wrapper that will be created')
    args = parser.parse_args()

    typedefs = []
    definitions = []
    # find all the function prototypes
    prototypes = re.findall('CK_PKCS11_FUNCTION_INFO\((.*?)\).*?\((.*?)\);',
        args.infile.read(), flags=re.DOTALL)
    args.infile.close()
    for name, raw_parameters in prototypes:
        typedef, definition = get_function(name, raw_parameters)
        typedefs.append(typedef)
        definitions.append(definition)
    args.outfile.write('{}\n\n{}\n\n{}'.format(
        get_prequel(), ''.join(typedefs), '\n'.join(definitions)))
    args.outfile.close()

if __name__ == '__main__':
    main()
