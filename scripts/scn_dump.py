import sys
import pefile

def main():
    if len(sys.argv) != 3:
        print('USAGE   :: scn_dump.py [FILE] [OUTPUT]')
        print('EXAMPLE :: scn_dump.py input.exe out.bin')
        return

    try:
        pe  = pefile.PE(sys.argv[1])
        fnd = False
        with open(sys.argv[2], 'wb+') as out:
            for section in pe.sections:
                # Assuming UTF-8 will work here...
                # Since PE section names are ANSI. Should work.
                if section.Name.replace(b'\x00', b'').decode('utf-8') == '.text':
                    print(f'++ Located .text section in PE file {sys.argv[1]}')
                    print(f'++ Section size: {len(section.get_data())}')
                    out.write(section.get_data())
                    fnd = True
                    break

            # Pretty much impossible as long as pefile.PE doesn't throw
            # You never know though!
            if fnd == False:
                print(f'!! PE file {sys.argv[1]} does not contain a .text section.')
            else:
                print(f'++ Success: dumped .text section of {sys.argv[1]} to output file {sys.argv[2]}.')

    except Exception as e:
        print(f'!! Fatal exception: {e}')

if __name__ == '__main__':
    main();    
        
