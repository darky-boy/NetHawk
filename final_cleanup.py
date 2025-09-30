#!/usr/bin/env python3
"""
Final cleanup of NetHawk.py - remove all old handshake capture code
"""

def final_cleanup():
    # Read the file
    with open('NetHawk.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Split into lines
    lines = content.split('\n')
    
    # Find the end of the first run function
    run_end = None
    for i, line in enumerate(lines):
        if 'except Exception as e:' in line and 'Unexpected error' in line:
            run_end = i + 1
            break
    
    if run_end is not None:
        # Keep only the lines up to the first run function
        clean_lines = lines[:run_end]
        
        # Add the main block
        main_block = [
            '',
            '',
            'if __name__ == "__main__":',
            '    main()'
        ]
        
        clean_lines.extend(main_block)
        
        # Write the cleaned content
        with open('NetHawk.py', 'w', encoding='utf-8') as f:
            f.write('\n'.join(clean_lines))
        
        print('SUCCESS: Final cleanup completed!')
        return True
    else:
        print('ERROR: Could not find run function end')
        return False

if __name__ == "__main__":
    final_cleanup()
