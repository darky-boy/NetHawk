#!/usr/bin/env python3
"""
Final cleanup - remove everything after main block
"""

def clean_final():
    # Read the file
    with open('NetHawk.py', 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # Find the main block
    main_start = None
    for i, line in enumerate(lines):
        if 'if __name__ == "__main__":' in line:
            main_start = i
            break
    
    if main_start is not None:
        # Keep only the lines up to the main block + 2 lines
        clean_lines = lines[:main_start + 2]
        
        # Write the cleaned content
        with open('NetHawk.py', 'w', encoding='utf-8') as f:
            f.writelines(clean_lines)
        
        print('SUCCESS: Final cleanup completed!')
        return True
    else:
        print('ERROR: Could not find main block')
        return False

if __name__ == "__main__":
    clean_final()
