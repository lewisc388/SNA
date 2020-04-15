#!/usr/bin/python3
#---------------------------------[Imports]------------------------------------
# Internal modules
import curses
import grp
import os
from os import path
import os.path
import pickle
import pwd
import subprocess
import sys
import traceback

# Downloaded modules
from termcolor import colored, cprint

# File imports
import scapyreader

#---------------------------------[Globals]------------------------------------
# Stores the base settings for base capture
global basesettings
basesettings = {
    'Interface':        '',
    'SSID':             '',
    'BaseCapPath':      '',
    'BaseFileName':     '',
    'PathFile':         '',  
    'RunTime':          '',
    'RunPeriod':        ''
}

global YorN
YorN = [
    "Yes",
    "No",
    "Go Back"
]

#--------------------------------[Functions]-----------------------------------
# Defined for error messages
def errors(err_num):
    error_list = [
        # Error 0: Sys Exit    
        (colored("[*] Exited.", 'blue')),
        # Error 1: Missing Sudo
        (colored("[*] Error: This program requires super user privlages.", 'red')),
        # Error 2: Bad or UNK input
        (colored("[*] Error: Invalid input. Try again.", 'red')),
        # Error 3: Bad or UNK path
        (colored("[*] Error: Specified path is invalid. Try Again.", 'red')),
        # Error 4: Exception error
        (colored("[*] Error: ", 'red'))
    ]

    if err_num == 0:
        # Exit curses screen, prints the error and exits program
        exitscr()
        print(error_list[0])
        sys.exit()

    if err_num == 4:
        # Exit curses screen, prints errors and exits program
        exitscr()
        print(error_list[4])
        traceback.print_exc(file=sys.stdout)
        sys.exit()

    elif err_num == '':
        return 1

    else:
        # Prints the error message
        print(error_list[err_num])
        input("Any key to continue... ")

# Clears the standard terminal screen
def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

# Determines if val is an integer value
def isinteger(val):
    try:
        x = int(val)
        return True
    except ValueError:
        return False

# Determines if directory path exists
def ispath(path):
    return os.path.exists(path)

# Verifies that user is running script with sudo
def issudo():
    if not 'SUDO_UID' in os.environ.keys():
        errors(1)
        sys.exit(1)

# Splits a word into a list of chars (for running commands)  
def split(word):
    return list(word)

# Setsup the screen to scroll, start colour, and use keys
def setupscr(stdscr):
    # Window is scrolled up one line when newline is added
    stdscr.scrollok(1)
    # Permits colour in terminal
    curses.start_color()
    # Allows use of key shortcuts
    stdscr.keypad(True)

# Cleanly exits the curses screen
def exitscr():
    # Restore cursor
    curses.curs_set(1)
    # Ends curses window
    curses.endwin()
    # Clears terminal screen
    clear() 

# Saves dictionaries and the likes as pickle objects
def save_obj(obj, name):
    with open('obj/'+ name + '.pkl', 'wb') as f:
        pickle.dump(obj, f)


# Used to drop sudo privlages when no longer needed.
def drop_privileges():
    if os.getuid() != 0:
        # We're not root so, like, whatever dude
        return

    # Get the uid/gid from the name
    user_name = os.getenv("SUDO_USER")
    pwnam = pwd.getpwnam(user_name)

    # Remove group privileges
    os.setgroups([])

    # Try setting the new uid/gid
    os.setgid(pwnam.pw_gid)
    os.setuid(pwnam.pw_uid)

    # Ensure a very conservative umask
    old_umask = os.umask(0o22)


# -----------------------------------------------------
# Will print a selection menu and return the results.
# This function takes in three lists:
# The title of the menu, any notes (such as "X to quit"),
# and an array with the provided options
def __PrintMenuOpts(title, notes, options):
    stdscr = curses.initscr()
    setupscr(stdscr)
    curses.curs_set(0)
    
    attributes = {}
    curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)
    attributes['normal'] = curses.color_pair(1)

    curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_WHITE)
    attributes['highlighted'] = curses.color_pair(2)

    c = 0
    select = 0

    # Will highlight the "selected" option and will return the option
    # when the user hits the enter key. Otherwise, the user may quit
    # the screen with 'x'.
    while c != 10 and c != '\n':
        # Clears the screen
        stdscr.erase()
        attr_norm = attributes['normal']

        # Displays the title
        for lines in title:
            stdscr.addstr(lines, attr_norm)
        # Displays any notes for the menu
        for lines in notes:
            stdscr.addstr(lines, attr_norm)

        for i in range(len(options)):
            # Prints the options highlighted if selected
            if i == select:
                attr = attributes['highlighted']
            else:
                attr = attributes['normal']

            stdscr.addstr("\t{0}) ".format(i+1))
            stdscr.addstr(options[i], attr)
            stdscr.addch('\n')
            
        c = stdscr.getch()

        # Interprets arrow keys and the exit key
        if (c == curses.KEY_UP or c == ord('w')) and select > 0:
            select -= 1
        elif (c == curses.KEY_DOWN or c == ord('s')) and select < len(options)-1:
            select += 1
        elif c == ord('x') or c == curses.KEY_EXIT:
            exitscr()
            errors(0)
    
        stdscr.refresh()

    curses.curs_set(1)
    stdscr.erase()
    exitscr()

    return options[select]
              
# Will print an input menu and return the results
# This function takes in three lists:
# The title of the menu, any notes (such as "X to quit"),
# and a prompt for input.        
def __PrintMenuInput(title, notes, prompt):
    # Initializes the curses screen and sets up the screen
    stdscr = curses.initscr()
    setupscr(stdscr)

    # Defines text attributes (colours)
    attributes = {}

    curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)
    attributes['normal'] = curses.color_pair(1)

    attr_norm = attributes['normal']

    # Displays the title
    for lines in title:
        stdscr.addstr(lines, attr_norm)
    # Displays any notes for the menu
    for lines in notes:
        stdscr.addstr(lines, attr_norm)
    # Displays the input prompt
    for lines in prompt:
        stdscr.addstr(lines, attr_norm)
    
    # Gets a string of user input
    usr_input = stdscr.getstr()

    if usr_input.decode() == 'x' or usr_input.decode() == 'X':
        # If the user specifies the exit key, cleanly exit the screen
        # and return an appropriate error message
        exitscr()
        errors(0)
        
    elif usr_input.decode() == '\n' or usr_input.decode() == '':
        stdscr.erase()
        exitscr()
        errors(2)
        __PrintMenuInput(title, notes, prompt)

    else: 
        # Clears and cleans the curses screen and returns 
        # the user's input   
        stdscr.erase()
        exitscr()
        return usr_input.decode()

# Defines the order of steps to complete the base setup
def __SetupSteps(Step, Redo):
    if Step == 1:
        __InterfaceOptions(Redo)
    elif Step == 2:
        __SetSavePath(Redo)
    elif Step == 3:
        __SetCapName(Redo)
    elif Step == 4:
        __SetTimeRun(Redo)
    elif Step == 5:
        __VerifyStart()

# Has the user specify which interface they wish to monitor
def __InterfaceOptions(Redo):
    Title = [
        "+----------------------------------------------+\n",
        "|      Step 1: Interface Monitor Selection     |\n",
        "+----------------------------------------------+\n",
        "\n"
    ]
    Notes = [
        "Please select an interface to monitor.              \n",
        "Use w(up) and s(down) keys to select. x to quit.\n",
        "Interfaces available:                               \n",
        "\n"
    ]
    Options = os.popen("ifconfig -a | sed 's/[ \\t].*//;/^\(lo\|\)$/d'").read()
    Options = Options.split('\n')
    Options.pop()
    
    
    #input("...")

    #Options = netifaces.interfaces()

    result = __PrintMenuOpts(Title, Notes, Options)

    # Parse the result
    if result in Options:
        # Sets the option if the returned result
        # is a specified option/ interface provided
        basesettings['Interface'] = str(result)

        # Gets the SSID of the selected interface
        __GetSSID()

        # If redoing a setting at verify, will return to 
        # the __VerifyStart() function, otherwise continues
        # to the next step in the setup
        if Redo == True:
            __VerifyStart()
        else:
            __SetupSteps(2, False)
    
    else:
        # If the input is invalid, will return an error and
        # restart the step.
        errors(2)
        __InterfaceOptions(Redo)

# Gathers the SSID name to ensure traffic is normative for that network
def __GetSSID():
    # Gets the SSID of the set interface by parsing the 
    # iwconfig command.
    ssid = os.popen("iwconfig "+ basesettings['Interface'] +" | sed -e \'/ESSID/!d\' -e \'s/.*ESSID:\"/\"/\'").read()
    ssid.rstrip()
    
    # Check if the SSID parsed is the valid SSID 
    # for the interface.
    Title = [
        "Is this SSID correct?\n",
        ("SSID: " + ssid + "\n")
    ]
    Notes = [
        "Use (up or w) and (down or s) keys to select. x to quit.\n"
    ]

    result = __PrintMenuOpts(Title, Notes, YorN)

    # Parse the result
    if result == "Go Back":
        # Go back to the Interface selection menu
        __InterfaceOptions(False)

    elif result == "No":
        # If the SSID found is incorrect, have the 
        # user specify what the correct SSID is.
        Title = [
            "Please enter the name of your network(SSID):\n"
        ]
        Notes = [
            "b to go back. x to quit.\n"
        ]
        Prompt = [
            "SSID: "
        ]

        result = __PrintMenuInput(Title, Notes, Prompt)

        # Parse the result
        if result == 'b' or result == 'B':
            # Go back to the previous step in the setup
            __GetSSID()
        else:
            # Set the input as the base setting SSID
            basesettings['SSID'] = str(result)
        
    elif result == "Yes":
        # If the SSID is correct, then set it
        # as the base setting SSID.
        basesettings['SSID'] = ssid
    
    else:
        # Otherwise, print an error and restart the step
        errors(2)
        __GetSSID()

# Has the user specify where they wish to save their base capture
def __SetSavePath(Redo):
    Title = [
        "+----------------------------------------------+\n",
        "|        Step 2: Base Capture Save Path        |\n",
        "+----------------------------------------------+\n",
        "\n"
    ]
    Notes = [
        "Please specify where you wish to save your base capture...\n",
        "Use d to use current working directory.\n", 
        "b to go back a step. x to quit.\n",
        "\n"
    ]
    Prompt = [
        "Path: "
    ]

    result = __PrintMenuInput(Title, Notes, Prompt)

    # Parse the result
    if result == 'b' or result == 'B':
        # To return back a step to redo it
        __SetupSteps(1, False)

    elif result == 'd' or result == 'D':
        # To use the default path for the base capture
        cwd = os.getcwd()
        # Checks that directory exists, and creates a directory
        # if it doesn't.
        if not os.path.exists(cwd + "/captures"):
            os.mkdir('captures')

        basesettings['BaseCapPath'] = cwd + "/captures"

        # Return back to __VerifyStart() or move to the next step
        if Redo == True:
            clear()
            __VerifyStart()
        else:
            __SetupSteps(3, False)

    elif ispath(result) == True:
        # If the path specified does exist
        basesettings['BaseCapPath'] = result
        #print("Path Selected is: " + basesettings['BaseCapPath'] + "\n\n")

        # Return back to __VerifyStart() or move to the next step
        if Redo == True:
            clear()
            __VerifyStart()
        else:
            __SetupSteps(3, Redo)
    
    elif ispath(result) == False:
        # If the path specified does not exist, print an error
        # and restart the step.
        errors(3)
        __SetSavePath(False)
    
    else:
        # If unknown input, print error and restart the step
        errors(2) 
        __SetSavePath(False)

# Has the user specify what they wish to save their base capture as
def __SetCapName(Redo):
    Title = [
        "+----------------------------------------------+\n",
        "|      Step 3: Base Capture Save Filename      |\n",
        "+----------------------------------------------+\n",
        "\n"
    ]
    Notes =[
        "Please specify what you wish to save the capture file as...\n",
        "Use d to use default (\"Base_Capture\"). \n",
        "b to go back a step. x to quit.\n",
        "\n"
    ]
    Prompt = [
        "Filename: "
    ]

    result = __PrintMenuInput(Title, Notes, Prompt)

    # Parse the result
    if result == 'b' or result == 'B':
        __SetupSteps(2, False)

    elif result == 'd' or result == 'D':
        # Use the default capture filename
        basesettings['BaseFileName'] = "Base_Capture"
        __DuplicateFile()

        # Return back to __VerifyStart() or move to the next step
        if Redo == True:
            __VerifyStart()
        else:
            __SetupSteps(4, False)
    
    else:
        # Use user specified filename
        basesettings['BaseFileName'] = str(result)
        __DuplicateFile()

        # Return back to __VerifyStart() or move to the next step 
        if Redo == True:
            clear()
            __VerifyStart()
        else:
            __SetupSteps(4, False)

# Has the user specify how long they want the base capture to run for
def __SetTimeRun(Redo):
    Title = [
        "+----------------------------------------------+\n",
        "|      Step 4: Set Run Time or Run Period      |\n",
        "+----------------------------------------------+\n",
        "\n"
    ]
    Notes = [
        "Please specify a run time or run period...          \n",
        "b to go back. x to quit.                            \n",
        "Formats:                                            \n",
        "hh:mm - Time of day to run until, in 24h format.    \n",
        "ex: 13:30 or 07:15                                  \n",
        "[num]d - Number of days to run.                     \n",
        "[num]h - Number of hours to run.                    \n",
        "[num]m - Number of minutes to run.                  \n",
        "ex: 2d 3h 30m or 1h 10m or 1d                       \n",
        "\n"
    ]
    Prompt = [
        "Time: "
    ]

    result = __PrintMenuInput(Title, Notes, Prompt)

    # Parse the result
    days = 0
    hours = 0
    mins = 0

    if result == 'b' or result == 'B':
        # Go back to previous step
        __SetupSteps(3, False)

    elif ":" in result and len(result) == 5:
        # Parse Runtime format
        basesettings['RunTime'] = result
        
        # Return back to __VerifyStart() or move to the next step
        if Redo == True:
            clear()
            __VerifyStart()
        else:
            __SetupSteps(5, False)

    elif " " in result:
        # Parse multiple run periods
        times = result.split(" ")
        time_len = len(times)
        for val in range(time_len):
            if times[val].endswith("d"):
                day = times[val]
                days = int(day[:-1])
            elif times[val].endswith("h"):
                hour = times[val]
                hours = int(hour[:-1])
            elif times[val].endswith("m"):
                minute = times[val]
                mins = int(minute[:-1])
        
        period = str(days) + ":" + str(hours) + ":" + str(mins)
        basesettings['RunPeriod'] = period

        # Return back to __VerifyStart() or move to the next step
        if Redo == True:
            clear()
            __VerifyStart()
        else:
            __SetupSteps(5, False)

    elif result.endswith("d"):
        # Parse day run period
        day = result
        days = int(day[:-1])
        period = str(days) + ":" + str(hours) + ":" + str(mins)
        basesettings['RunPeriod'] = period
        
        # Return back to __VerifyStart() or move to the next step
        if Redo == True:
            clear()
            __VerifyStart()
        else:
            __SetupSteps(5, False)

    elif result.endswith("h"):
        # Parse hour run period
        hour = result
        hours = int(hour[:-1])
        period = str(days) + ":" + str(hours) + ":" + str(mins)
        basesettings['RunPeriod'] = period
        
        # Return back to __VerifyStart() or move to the next step
        if Redo == True:
            clear()
            __VerifyStart()
        else:
            __SetupSteps(5, False)

    elif result.endswith("m"):
        # Parse minute run period
        minute = result
        mins = int(minute[:-1])
        period = str(days) + ":" + str(hours) + ":" + str(mins)
        basesettings['RunPeriod'] = period
        
        # Return back to __VerifyStart() or move to the next step
        if Redo == True:
            clear()
            __VerifyStart()
        else:
            __SetupSteps(5, False)

    else:
        # If invalid input, print error and restart step
        errors(2)
        __SetTimeRun(Redo)

# Verifies the settings the user has chosen
def __VerifyStart():
    Title = [
        "+----------------------------------------------+\n",
        "|            Step 5: Verify Setting            |\n",
        "+----------------------------------------------+\n",
        "\n"
    ]
    Notes = [
        "Are these settings correct?   \n",
        "b to go back. x to quit.      \n",
        "------------------------------\n",
    ]
    # Takes the currently set settings and appends it to the Notes
    for settings in basesettings:
        if basesettings[settings] != '':
            Notes.append((settings + ": " + (basesettings[settings].rstrip()) + '\n'))
    Notes.append('\n')

    result = __PrintMenuOpts(Title, Notes, YorN)

    # Parse the result
    if result == "Go Back":
        # Returns back to the previous step
        __SetupSteps(4, False)

    elif result == "Yes":
        # Accepts the settings and saves them to a pkl object,
        # then goes and starts the base capture
        save_obj(basesettings, 'settings')
        __RunBase()

    elif result == "No":
        # If the user wants to change a setting, have them specify which
        Title = [
            "Which setting would you like to change?\n"
        ]
        Notes = [
            "x to quit.\n",
        ]
        Options = [
            "Go Back",
            "Interface Monitor Selection",
            "Base Capture Save Path",
            "Base Capture Save Filename",
            "Set Run Time or Run Period",
        ]

        result = __PrintMenuOpts(Title, Notes, Options)
        resval = Options.index(result)

        # Parse the result
        if resval == 0 or result == "Go Back":
            # Goes back to the previous step
            __VerifyStart()
        else:
            # Goes back to the specified step and will
            # return back to Verify after step is 
            # completed.
            __SetupSteps(resval, True)
    
    else:
        # Display an error and restart the step
        errors(2)
        __VerifyStart()

# Asks the user if they would like to calculate the stats of the provided file
def __RunStats():
    Title = [
        "+----------------------------------------------+\n",
        "|                   Run Stats                  |\n",
        "+----------------------------------------------+\n",
        "\n"
    ]
    Notes = [
        "Would you like to generate stats\n",
        "for this capture?               \n",
        "x to quit.                      \n",
        "--------------------------------\n"
    ]
    options = [
        "Yes",
        "No"
    ]

    result = __PrintMenuOpts(Title, Notes, options)

    if result == "No":
        exit(1)
    elif result == "Yes":
        command = "python3 pcapstats.py " + basesettings['PathFile'] + " > " + basesettings['BaseCapPath'] + '/' + basesettings['BaseFileName'] + ".txt"
        os.system(command)
        print("Stats outputted to " + "stats/" + basesettings['BaseFileName'] + ".txt")


def __DuplicateFile():
    global basesettings

    pathfile = (basesettings['BaseCapPath'] + '/' + basesettings['BaseFileName'])

    if os.path.exists((pathfile + '.pcap')):
        i = 1
        while os.path.exists((pathfile + str(i) + '.pcap')):
            i += 1
        log_pcap = pathfile + str(i) + '.pcap'
    else:
        log_pcap = pathfile + '.pcap'
    
    basesettings['PathFile'] = log_pcap

    
# Runs the base capture
def __RunBase():
    global basesettings
    clear()
    print(colored("Running Scan. Please do not close this terminal!\n", 'green'))
    bc = scapyreader.BaseCap()
    #drop_privileges()
    __RunStats()


#----------------------------------[Main]--------------------------------------
def __Main():
    try:
        # Checks if the program is running with sudo privilages,
        # then starts the setup steps
        issudo() 
        __SetupSteps(1, False)

    except KeyboardInterrupt:
        # Cleanly exits if user enters a keyboard interrupt, ie. ^C
        errors(0)

    except Exception:
        # If a program error occurs, cleans the screen and then shows
        # the program error.
        errors(4)
    
    # Cleans screen again, just in case
    #exitscr()

#-----------------------------------[Run]--------------------------------------
__Main()
#------------------------------------------------------------------------------