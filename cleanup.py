#!/usr/bin/env python3
"""
Clean up NetHawk.py by removing all old handshake capture code
"""

def clean_netHawk():
    # Read the file
    with open('NetHawk.py', 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # Find the end of the run function
    run_start = None
    run_end = None
    
    for i, line in enumerate(lines):
        if 'def run(self):' in line:
            run_start = i
        elif run_start is not None and line.strip().startswith('if __name__ == "__main__":'):
            run_end = i
            break
    
    if run_start is not None and run_end is not None:
        # Keep only the lines up to the run function and the main block
        clean_lines = lines[:run_start]
        
        # Add the clean run function
        run_function = '''    def run(self):
        """Main application loop."""
        try:
            # Display logo and check tools
            self.display_logo()
            
            while True:
                self.display_main_menu()
                choice = self.validate_input(
                    "\\n[bold]Select an option:[/bold] ",
                    ["1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "Q"]
                )
                
                if choice == "1":
                    self.passive_wifi_scan()
                elif choice == "2":
                    self.aggressive_active_scan()
                elif choice == "3":
                    self.advanced_handshake_capture()
                elif choice == "4":
                    self.vulnerability_assessment()
                elif choice == "5":
                    self.web_application_scanning()
                elif choice == "6":
                    self.dns_reconnaissance()
                elif choice == "7":
                    self._display_hybrid_detection_explanation()
                elif choice == "8":
                    self._bypass_protections_tips()
                elif choice == "9":
                    self._display_hybrid_detection_explanation()
                elif choice == "A":
                    self._bypass_protections_tips()
                elif choice == "B":
                    self._bypass_protections_tips()
                elif choice == "Q":
                    console.print("\\n[bold green]Thank you for using NetHawk![/bold green]")
                    break
                    
        except KeyboardInterrupt:
            console.print("\\n[yellow]Goodbye![/yellow]")
        except Exception as e:
            console.print(f"[red]Unexpected error: {e}[/red]")
'''
        
        clean_lines.extend(run_function.split('\n'))
        clean_lines.append('')
        clean_lines.extend(lines[run_end:])
        
        # Write the cleaned content
        with open('NetHawk.py', 'w', encoding='utf-8') as f:
            f.writelines(clean_lines)
        
        print('SUCCESS: Cleaned up NetHawk.py successfully!')
        return True
    else:
        print('ERROR: Could not find function boundaries')
        return False

if __name__ == "__main__":
    clean_netHawk()
