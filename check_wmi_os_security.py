#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# =============================================================================
# Name: check_wmi_os_security.py
# Scipt for check not only Windows OS security information by WMI
# https://github.com/Louda-Jan/check_wmi_os_security
#
#
# The script use WMIC Server to connect Windows WMI:
# https://github.com/cesbit/aiowmi/tree/main/contrib/wmic_server
#
# The script follows Nagios:
# https://nagios-plugins.org/doc/guidelines.html
#
# Author: Jan Louda
#
# =============================================================================
# :::CHANGELOG:::
# 0.84 - Add --count and --null-output cli
# 0.83 - Add --null
# 0.82 - Add --human-readable
# 0.81 - The first release of the publication
# =============================================================================


# IMPORT PYTHON MODULES =======================================================
"""System module."""
import getopt
import sys
import copy
import json
import textwrap
import re
import configparser
from datetime import datetime, timedelta
import requests


# VARIABLES ===================================================================
# [:::user define variable:::]
wmi_server_url = 'http://127.0.0.1:2313/wmic'             # URL for wmic_server
requests_timeout = 10         # default timeout (sec) for python request module
args_inifile = "/opt/check_wmi_os_security/args.ini"

# [:::script variables:::]-----------------------------------------------------
script_version = '0.84'
last_modify = '[2023/03]'
name_of_script = './check_wmi_os_security.py'
script_author = 'Louda Jan (j.louda_at_email.cz)'
script_github = 'https://github.com/Louda-Jan/check_wmi_os_security'
example_host = 'myserver01.test.local'
token_in_help = 'MYTOKEN1'
window_width = 101
help_window_width = 119
# alias
debug_sep = (window_width * "-")
appo = '\''
add_dq = '\"'
comma = ','
semi = ';'
msg_output = ''

example_cli = (f"{name_of_script} -U user1 -T {token_in_help} -H "
               f"{example_host} --query=os")

help_usage = (
    f"Basic usage: {name_of_script} -U ID -T TOKEN -H FQDN/IP -q "
    f"[CHECK OPTIONS] [GLOBAL OPTIONS] [-w <warn>] \n               "
    "[-c <crit>] [-t timeout] [ -d debug]"
)

# value for arguments items
args_debug = False
args_list_services = False
args_print_wmidata = False
args_services = False
args_check_one = False
args_name = False
args_unitperf = False
args_no_perfdata = False
args_no_extdata = False
args_msg_desc = ""
args_msg_desc_ext = ""
args_args_ini = False
args_null = False
args_null_output = False
args_datetime = False
args_human_readable = False
args_count = False
args_warning = False
args_critical = False
args_warning_str = False
args_critical_str = False
args_reqex_full = False
args_reqex_search = False
args_invert = False
args_one_found = False
args_multi = False
args_wql = False
args_namespace = "root/cimv2"
args_logfile = "Application"
args_loglevel = 3
args_timeback = "4h"
args_eventid = False
args_eventsource = False
args_eventcategory = False
args_eventmsg = False
args_event_not = False
args_xxx = False
# mandatory prameters
args_userid = 'None'
args_token = 'None'
args_host = 'None'
args_query = 'None'
# service arguments
msg_output = ''
# nagios return code
stdout_ok = 0
stdout_warning = 1
stdout_critical = 2
stdout_unknown = 3
# define empty list for global function
perfdata = ""
return_data_list = ""
return_data_dict = ""
name_services_dict = {}
data_dict = ""
wmi_data = ""
services_list = ""
services_list_cho = ""
name_list = ""
unit_perf_list = ""
threshold_list = ""
perfdata_dict = ""
event_found = ""
extend_data = ""


# CLASS =======================================================================
# [:::COLOR:::]
# thanks you: https://gist.github.com/tuvokki/14deb97bef6df9bc6553
class bcolors:
    """Class for color in text"""
    HEADER = '\033[93m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    W = '\033[93m'
    HEADER = '\033[37m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    # [:::print help text yellow:::]
    @staticmethod
    def yellow(text, desc):
        """For print yellow text"""
        print(
            bcolors.W + str(text) + bcolors.ENDC + desc, end=""
            )

    # [:::print text bold:::]
    @staticmethod
    def boldbg(text):
        """For print bold text"""
        print(
            bcolors.BOLD + str(text) + bcolors.ENDC, sep="\n"
            )

    # [:::print text FAIL/ERROR:::]
    @staticmethod
    def fail(input_text):
        """Function print boldbold text. Aligment width"""
        wrapper = textwrap.wrap(text=input_text, width=window_width)
        # print each line.
        for v in wrapper:
            print(bcolors.FAIL + v + bcolors.ENDC)

    # [:::print text FAIL/ERROR without wrap:::]
    @staticmethod
    def fail_w(text):
        """Function print boldbold text without wrap """
        print(bcolors.FAIL + str(text) + bcolors.ENDC)

    # [:::print text title:::]
    @staticmethod
    def title(text):
        """Function print boldbold text without wrap """
        print(bcolors.HEADER + str(text) + bcolors.ENDC)

    @staticmethod
    def title_w_text(text, text2):
        """Function print boldbold text without wrap """
        print(str(text) + bcolors.HEADER + str(text2) + bcolors.ENDC)

    # [:::print text title for help and query:::]
    @staticmethod
    def title_query(text, text2):
        """Function print boldbold text without wrap """
        print(bcolors.HEADER + str(text) + bcolors.ENDC, str(text2))

    # [:::print text HEDERS :::]
    @staticmethod
    def header_help(text):
        """Function print header text with wrap """
        wrapper = textwrap.wrap(text=text, width=help_window_width)
        # print each line.
        for v in wrapper:
            print(bcolors.HEADER + v + bcolors.ENDC)


# FUNCTION [00] ARGS FROM INI =================================================
def menu_args_ini():
    """Function read only --args-ini arguments"""

    l1 = sys.argv
    l2 = []
    l1_index = 0

    argument1 = "--args-ini="
    argument2 = "--args-ini"
    argument3 = "-x"

    for i in l1:
        l1_index += 1
        if argument1 in i:
            l2 = i.split('--args-ini=')
        elif argument2 in i:
            print(l1[l1_index])
            l2.append("")
            l2.append(l1[l1_index])
        elif argument3 in i:
            l2.append("")
            l2.append(l1[l1_index])

    if len(l2) > 0:
        return str(l2[1])
    else:
        return False


def args_from_ini_load_opt(section: str):
    """Function read opriotn from ini file"""

    # read ini file
    config = configparser.ConfigParser()
    try:
        config.read(args_inifile)
    except configparser.DuplicateSectionError as error:
        msg = (f"[ERROR {type(error).__name__}] "
               f"The problem in the ini file '{args_inifile}' are duplicate "
               f"sections '[]'.")
        print(msg)
        sys.exit(stdout_unknown)

    try:
        return config.options(f"{section}")
    except (configparser.NoSectionError, configparser.NoOptionError) as error:
        msg = (f"[ERROR {type(error).__name__}] "
               f"No read ini file '{args_inifile}' or section:'{section}' "
               f"or options not exist.")
        print(msg)
        sys.exit(stdout_unknown)


def args_from_ini_items(section: str, opt01: str):
    """Function read argumentsment from ini file"""

    string_val = ""

    # read ini file
    config = configparser.ConfigParser()
    config.read(args_inifile)

    try:
        string_val = config.get(f"{section}", f"{opt01}")
    except (configparser.NoSectionError, configparser.NoOptionError) as error:
        msg = (f"[ERROR {type(error).__name__}] "
               f"No read ini file '{args_inifile}' or section:'{section}' "
               f"or opt01:'{opt01}' not exist.")
        print(msg)
        sys.exit(stdout_unknown)

    return string_val


# FUNCTION [01] DEBUG =========================================================
# [:::debug:::] - one line debug info :::::::::::::::::::::::::::::::::::::::::
def dbg(text: str, debug_text: str) -> None:
    """For debug messages"""
    if args_debug:
        print(str(text) + "\t" + "[", type(debug_text), "]" + "\t" + ": " +
              bcolors.W + str(debug_text) + bcolors.ENDC, end="" + "\n")


def dbg_alignment(text: str, debug_text: str) -> None:
    """For debug messages to remove "\n" from debug_text and print"""
    if args_debug:
        debug_text = debug_text.replace('\n', ' ')
        print(str(text) + "\t" + "[", type(debug_text), "]" + "\t" + ": " +
              bcolors.W + str(debug_text) + bcolors.ENDC)


# [:::debug separator:::] :::::::::::::::::::::::::::::::::::::::::::::::::::::
def dbg_separator(text: str):
    """ For debug separate """
    before_str = str((64 * "-") + "[")
    after_str = str("]")
    line_len = window_width - len(text) - len(before_str) - len(after_str) - 2

    if args_debug:
        if text == "":
            print((window_width - 1) * "-")
        else:
            print(before_str + text + after_str, line_len * "-")


# [:::help short:::] ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
def f_help_short():
    """Display short help"""
    print(
        f"{bcolors.FAIL}Not all mandatory parameters are defined!"
        f"{bcolors.ENDC}"
        " [--user=, --token=, --host=, --query=]"
        f" \n\n{help_usage},"
        f"\n\nExample:    {example_cli}"
        f"\nPrint help: {name_of_script} --help"
        )


# FUNCTION [02] HELP ==========================================================
# [:::help completed:::] ::::::::::::::::::::::::::::::::::::::::::::::::::::::
def f_help_full():
    """Function for print help"""

    f_help_full_header()
    f_help_full_basic_opt()
    f_help_full_check_opt()


# [:::help HEADER:::] :::::::::::::::::::::::::::::::::::::::::::::::::::::::::
def f_help_full_header():
    """function for  f_help_full HEADER """
    # bcolors.header_help(
    #                     f"{name_of_script} version: '{script_version}'. "
    #                     f"Monitoring not only Windows security "
    #                     "components by WMI. Tested on Win Server 2019/2022 "
    #                     "64-bit.")
    bcolors.title(
        f"NAME:\n  {name_of_script} version: '{script_version}'. Monitoring "
        "not only Windows security components by WMI. Tested on \n    Windows "
        "Server 2019/2022 64-bit. Tested on Python version: 3.6.8")

    bcolors.title("\nDESCRIPTION:")
    print("""  The script was designed to be universal in order to be able to monitor any WMI item and by composing multiple
  services to display/monitor the desired item. It is not designed for monitoring classic performance metrics of
  CPU, RAM, etc. where it is necessary to average and store performance data for evaluation (check_wmi_plus is
  ideal for this purpose 'https://edcint.co.nz/checkwmiplus').

  Script use WMIC Server to connect Windows WMI. Is necessary to have a functional wmic_server. Parameters (url and
  TCP/IP port) of wmic_server can be changed in 'VARIABLES' at the beginning of the script. Default TCP/2313'
  listening on '127.0.0.1'.""")

    bcolors.title_w_text(
        "\n  - Download and more information about 'wmic_server':",
        " https://github.com/cesbit/aiowmi/tree/main/contrib/wmic_server")

    bcolors.title_w_text(
        "  - The instructions for installing vmic_server on Debian 11 :",
        " https://github.com/Louda-Jan/check_wmi_os_security")

    bcolors.title_w_text(
        "  - The script follows NAGIOS Development Guidelines:",
        " https://nagios-plugins.org/doc/guidelines.html")

    print("""  - Basic information about WMI, custom WMI queries (WQL), etc. are available using the '--list-services' argument
   (example: '--query=os --list-services').""")

    bcolors.title("\nARGUMENTS:")
    print("""  Arguments are divided into three categories:
  [BASIC OPTIONS]  - Basic arguments regarding the connection.
  [GLOBAL OPTIONS] - Global arguments that can be used for all '--query='.
  [CHECK OPTIONS]  - Some query have own arguments that can only be used with this query (example --query=eventlog).
""")

    bcolors.title("USAGE:")
    print(f"  {help_usage}")

    bcolors.title("\nDESCRIPTION OF THE EXAMPLES:")
    print("""  For clarity of notation, all examples are given without connection arguments:
  './check_wmi_os_security.py -U ID -T TOKEN -H FQDN/IP'""")


# [:::help BASIC OPTIONS:::] ::::::::::::::::::::::::::::::::::::::::::::::::::
def f_help_full_basic_opt():
    """function for  f_help_full BASIC OPTIONS """

    bcolors.title("\nBASIC OPTIONS:")
    print("""------------------------------------------------------------------------------------------------------------------------
  -U, --user=USERNAME  The ID authentication on wmic_server. Default in wmic_server.yaml is 'user1'
  -T, --token=TOKEN    Authentication token. Default in wmic_server.yaml is 'MYSECRETUSERACCESSTOKEN1'
  -H, --host=FQDN/IP   Windows host for minitoring by WMI QUERY
  -A, --url=URL        The 'wmic_server' URL. Default in variable 'wmi_server_url' is 'http://127.0.0.2:2313/wmic'
  -t, --timeout=NUMBER Default is '30'(sec). Maximum time in sec. that you allow request connection to HOST
  -d, --debug          Debug mode. Ideal for viewing WMI class and WQL :)
  -V, --version        View script version, last modified date and GitHub link URL
  -h, --help           Show complete help information""")

    bcolors.title("\nGLOBAL OPTIONS:")
    print("""--------------------------------------------------------------------------------------------------------------------\
----
  -q, --query=         [STRING] Selection of predefined checks. Described in more detail in CHECK OPTIONS.

  -s, --services=      [STRING] Defining own monitoring services. It is possible to define multiple services separated
                       by a comma "," and enclosed in quotation marks " " (example: --services="Name,Status,FullName").
                       The list must be case-sensitive!. Performance data is automatically for numerical value only.

  -l, --list-services  Links and options for what services to monitor for WMI classes used in the --query query. Basic
                       information about WMI is also explained here

  -p, --print-wmidata  Prints real data (services/data) for the corresponding WMI class. Ideal when using defining your
                       own services or defining your own WMI WQL query '--query=wql'.  A good way to define thresholds
                       as well.

  -k, --check-one=     [STRING] With this option, it is possible to select multiple services for display, but select
                       only one for the threshold (warning/critical).
                       [Example:]
                       -Displaying information from all three services Name, Lockout, Status. Only the 'Status'service
                       will be used as a threshold (status warning is OK for 4 users, therefore 4x OK).
                        --query=wql --wql="SELECT Name,Lockout,Status from Win32_UserAccount" --namespace="root/cimv2"
                            --services="Name,Lockout,Status" --check-one=Status --warning-str="OK,OK,OK,OK"

  -n, --name=          [STRING] Defining your own description of selected items in '--services'. To monitor multiple
                       '--services', the same number of units as services must be specified. It needs to be
                       entered in the same order as services. List must separated by ',' and enclosed in " ".

  -u, --unitperf=      [STRING] Specifying custom units for performance data for '--services'. To monitor multiple
                       '--services', the same number of units as services must be specified. List must be separated by
                       ',' and enclosed in " ".According to Nagios Development Guidelines, possible measurement units:
                       (s) seconds (also us, ms) ; (%) - percentage; (B) - bytes (also KB, MB, TB) ; (c) - a continous
                       counter.
                       [Example:] --query=os --services="FreePhysicalMemory,FreeVirtualMemory" --unitperf=B,B

  -e, --no-perfdata    Turn off performance data. If the output of the monitored service is a number, the script
                       automatically creates performance data. In some cases it is desired to disable this behavior.

  -j, --no-extdata     Removes Extended status information from the output.

  -y, --msg-desc=      [STRING] Adds a custom description to the beginning of the output. Ideal for describing
                       monitoring services.

  -z, --msg-desc-ext=  [STRING] Adds a custom description to Extended status. Can be used ("," - is new line). Ideal
                       to use for describing EventID logs when checking multiple IDs. Real examples are in
                       'args-sample.ini'.
  -x, --args-ini=      Using a *.ini file to compose arguments. No need to enter complex/long syntax into the monitoring
                       engine. Centrally managed any changes. There is a small usage description and examples in
                       'args-sample.ini'.
                       DO NOT EDIT "args-sample.ini" will be updated regularly as new versions are released. The
                       procedure is 'cp args-sample.ini args.ini'. The absolute path to the "args.ini" file is the
                       beginning of the script variable named 'args_inifile ='. Usage examples are in '--query=eventlog'.

  -N, --null           If the query returns empty data. For example, for WQL queries. With empty data, the script
                       returns an error with this argument no.

  -Q, --null-output    It will not show the complete data from the monitored item. Ideal when the query returns a large
                       amount of data. Sample in 'args-sample.ini'.

  -D, --datetime=      [STRING] If the output is a date/time, this parameter will convert to a number format in days,
                       hours, minutes or seconds as necessary, so that it can be used as number for warning or critical.
                       Possible values are: 'd', 'h', 'm' or 's'.
                       [Example:]
                         --query=uptime --services="LastBootUpTime" --name="OS Uptime (Hours) is" --datetime=h

  -L, --human-readable= [STRING] Converts bytes to specified units (MB, KB, GB, TB). Windows WMI output is in bytes.
                        Possible values are: 'KB', 'MB', 'GB' or 'TB'.
                        Example: '--human-readable=GB'.

  -b, --count          For warning and critical only (not for -warning-str,--critical-str), the threshold is the number
                       of occurrences for the monitored item. Sample in 'args-sample.ini'. If you also want an OK count
                       display status, use '--null-output'.

  -w, --warning=       [NUMBER] Return WARNING/CRITICAL for defined monitoring service. Accepts Nagios
  -c, --critical=      threshold https://nagios-plugins.org/doc/guidelines.html#THRESHOLDFORMAT and ranges (Example:
                       10.3:20.5; ~:10.5; 10: ). It is possible to monitor multiple services, but the first match means
                       WARNING/CRITICAL.

  -W, --warning-str=   [NUMBER/STRING/REGEX] Return WARNING/CRITICAL for defined monitoring service.Threshold can be
  -C, --critical-str=  a number, text or regular expression and is not case-sensitive. If the expression matches it is
                       True (RETURN OK).
                       It is possible to track services that return multiple values, but the first mismatch means
                       WARNING/CRITICAL or use "--one-found". For services that return multiple values, you can define
                       multiple thresholds. List must separated by ',' and enclosed in " ". Thresholds must be defined
                       consecutively in the same way that service values are returned.
                       Additional arguments (--regex-full and --regex-search) need to be used for regular expressions,
                       explained below.
                       [Example:] The monitoring service returns: Name: ['Administrator', 'johnd', 'Pokuston']
                       For the script to return OK, it must be --critical-str="Administrator,johnd,Pokuston"
""")
    bcolors.boldbg("                       [ADDITIONAL ARGUMENTS FOR ONLY '--warning-str=' and '--critical-str=']")
    print("""       -r, --regex-full    Can use regular expresions. Warning or critical if the whole string matches the regular
                           expression pattern.

       -g, --regex-search  Can use regular expresions. Scan through string looking for the first location where the
                           regular expression pattern produces a match.

       -i, --invert        Inverted if the string matches (FOUND = WARNING/CRITICAL).

       -f, --one-found     For data that returns multiple items. If at least one match (RETURN OK).""")
    bcolors.boldbg("\n\n TIP: To debug matches and non-matches it is ideal to use '--debug' and below is the result of "
                   "comparing return data and \n thresholds. Name is 'Compare thresholds with return_data:'")


# [:::help CHECK OPTIONS:::] ::::::::::::::::::::::::::::::::::::::::::::::::::
def f_help_full_check_opt():
    """function for  f_help_full CHECK OPTIONS """
    bcolors.title("\n\nCHECK OPTIONS:")
    print("""--------------------------------------------------------------------------------------------------------------------\
----""")

    bcolors.boldbg("For a better understanding of the logic of the arguments, "
                   "some queries also include internally assembled arguments"
                   ".")
    print(""". . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .\
. . . . . . .""")
    bcolors.title_query(" --query=os",
                        "         Check OS information. If the --services is"
                        " not defined, it display the preset OS output.\n")
    print("""                     [:::Query Example:::]
                     :Displays real data for all services in a given WMi class.
                       --query=os --print-wmidata

                     :Displays output for 3 self-describing services.
                       --query=os -s 'Caption,CSName,Locale,CurrentTimeZone' --name="OSName,Hostname,Locale,TimeZone"

                     :Monitoring the number of current processes with thresholds.
                       --query=os --services='NumberOfProcesses' --warning=142 --critical=145
. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .\
""")

    bcolors.title_query(" --query=firewall",
                        "   Checks on/off firewall zones (domain, Private, Public).")
    print("""
                     [:::Query Example:::]
                     :Check has the following arguments internally defined:
                       --query=firewall --services="Name,Enabled" --name="Zone,Enabled"
                            --critical-str="domain,private,public,1,1,1"
. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .\
""")

    bcolors.title_query("  --query=eventlog",
                        "   The main tool for checking windows security. In order for OS Windows to audit the entries "
                        "used in \n                      'args-sample.ini'. Since there are usually a large number of "
                        "logs, you need to start with \n                      '--timeout' at least 30 sec.\n"
                        "                      For Security log advanced auditing must be set using GPO. "
                        "Instructions are described at \n"
                        "                      https://github.com/Louda-Jan/check_wmi_os_security/"
                        "#7-gpo---advanced-audit-configuration-for-a-security-log\n"
                        "                      The WMI user/group for WMI monitoring must be a member of the 'Event Log Readers' Group.")

    print("""
    --logfile=        [STRING] Select LogFile. They are basic: Application, System and Security. It is possible to enter
                      multiple items, but the list must be separated by "," and enclosed in "". It is also possible to
                      monitor other types of Windows logs (for example "Microsoft-Windows-PowerShell/Operational"), but
                      you need to modify the Registries according to the instructions in the args-sample.ini section
                      [eventlog-security05]. I have used this link in the past:
                      https://docs.datadoghq.com/integrations/guide/add-event-log-files-to-the-win32-ntlogevent-wmi-class/

    --loglevel=       [NUMBER] Log level in numbers default is '3'.
                      Number are: 1-Error, 2-Warning, 3-Information,4-Security Audit Success, 5-Security Audit Failure.
                      It is possible to enter multiple types separately ",". Example: --level="1,2" is Error or Warning

    --timeback=       [NUMBER/h or NUMBER/m] Number of hours/minutes backwards for log dump. Is not set default is '4h'
                      (4 hours). For example, in the case of Security logs, the script goes through a large number of
                      logs, so be careful with times longer than '--timeback=24h' (or increase --timeout=30 or more).

    --eventid=        [NUMBER] The Event ID number to display. It is possible to enter multiple items, but the list must
                      be separated by "," and enclosed in "".

    --eventsource=    [STRING] In Windows Event Viewer Item is 'Source' in WMI 'SourceName'.

    --eventcategory=  [STRING] In Windows Event Viewer Item is 'Task Category' in WMI is 'CategoryString'. Example usage
                      is in 'args-sample.ini'.

    --eventmsg=       [STRING]' Event message. String must be enclosed in quotation marks "". It is possible to use LIKE
                      Operator example usage is in 'args-sample.ini'. More information:
                      https://learn.microsoft.com/en-us/windows/win32/wmisdk/like-operator
                       [ ] - Any one character within the specified range ([a-f]) or set ([abcdef]).
                        ^  - Any one character not within the range ([^a-f]) or set ([^abcdef].)
                        %  - Any string of 0 (zero) or more characters. The following example finds all instances where
                             "Win" is found anywhere in the class name:
                             SELECT * FROM meta_class WHERE __Class LIKE "%Win%"
                        _  - Any one character. Any literal underscore used in the query string must be escaped by
                             placing it inside [] (square brackets).

    --event-not=      Possible values (eventsource,eventmsg,eventid,loglevel,logfile). In WQL filter means NOT.
                      For example: '--eventmsg=%VSS% --event-not=eventmsg' means all entries except message containing
                      the word 'VSS' (WQL je: "AND NOT Message LIKE '%VSS%'"). Example usage is in 'args-sample.ini'.
                      It is possible to enter multiple items, but the list must be separated by "," and enclosed in "".

    --check-one=Found Special service for '--query=eventlog' which is used for threshold. Indicates the number of
                      entries matching the defined filter for the eventlog.
                      [Example:]
                      :If the filter defined in 'args-sample.ini' in the [eventlog-security02] section finds at least
                      one entry, the check will be critical.
                      --query=eventlog --args-ini=eventlog-security02 --critical=0 -t 30
""")

    print("""                    [:::Query Example:::]""")
    bcolors.title("\t\t    MOST OF THE SAMPLES AND MAINLY PREDEFINED SECURITY INCIDENTS ARE IN 'args-sample.ini'.")
    print("""                    :Checking if someone did DUMP memory.
                      --query=eventlog --args-ini=eventlog-security02 --critical=0 -t 30

                    :Security issue with logs. Someone or something deleted the log :)
                      --query=eventlog --args-ini=eventlog-security01 --critical=0 -t 30

                    :Searching in the System log for the last 24 hours contains eventid 44 and message 'Windows Update.'
                     --query=eventlog --logfile=System --timeback=24h --eventid=44 --eventmsg="%Windows Update%"

                    :It is for demonstration. All logs in the Application for the last 4 hours except for EventID 1001.
                     --query=eventlog --logfile=Application --timeback=4h --eventid=1001 --event-not=eventid

                    [:::Query Tips:::]
                    :Display the names of available logs for WMI. Ideal for checking the correctness of registry
                    modifications, see args-sample.ini:
                      --query=wql --wql="SELECT * FROM Win32_NTEventlogFile" -s FileName

. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .\
""")

    bcolors.title_query(" --query=network",
                        "    Monitors network interfaces information TCP/IP.")
    print("""
                     [:::Query Example:::]
                     :Check DNS servers in TCP/IP. Will return CRITICAL if they are not '192.168.10.242,192.168.10.243'
                       --query=network --services=DNSServerSearchOrder --name="DNS Servers"
                            --critical-str="192.168.10.242,192.168.10.243"

                     :Displays real data for all services in a given WMi class.
                       --query=network --print-wmidata

. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .\
""")

    bcolors.title_query(" --query=dnscache",
                        "   Monitoring DNS cache. Probably just for information.")
    print("""
                     [:::Query Example:::]
                     :Predefined check in the script if I only use --query=
                       --query=dnscache --services="Name,Data,TimeToLive" --no-perfdata

. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .\
""")

    bcolors.title_query(" --query=users",
                        "      Monitors internal Windows Users. Ideal for monitoring user manipulation. Separate"
                        " monitoring of \n                     local accounts is done using Security event logs "
                        "(args-sample.ini section [eventlog-security03])")
    print("""
                     [:::Query Example:::]
                     :Predefined check. Returns CRITICAL if there are more local users than 'Administrator'
                       --query=users --args-ini=users-01 --critical-str="Administrator"

                     :Returns CRITICAL if there are more local users than 'Administrator,John Deal'. Check also
                     displays additional 'Lockout, Status' data.
                       --query=users --services="Name,Lockout,Status" --check-one=Name
                            --critical-str="Administrator,John Deal"

. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .\
""")

    bcolors.title_query(" --query=lockusers",
                        "  Monitoring lockdown of local accounts. Ideal for monitoring brute force password attacks.\n"
                        "                     Attention: The Administrator account cannot be locked.")
    print("""
                     [:::Query Example:::]
                     :Returns CRITICAL if at least one local account is locked.
                       --query=lockusers --services="Lockout,Name" --name="Lockout local users,Local users"
                            --check-one="Lockout" --one-found --invert --critical-str="True"

. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .\
""")

    bcolors.title_query(" --query=uptime",
                        "     Windows uptime monitoring. Ideal information about servers that haven't had a patch "
                        "\n                    (Windows update) installed in a long time.")
    print("""
                     [:::Query Example:::]
                     :Returns WARNING if uptime is greater than 40 days and returns CRITICAL if it is greater than
                     60 days.
                       --query=uptime --warning=40 --critical=60
                     :Predefined check in the script if I only use --query=
                       --query=uptime --services="LastBootUpTime" --name="OS Uptime (Days)  is" --datetime=d

. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .\
""")

    bcolors.title_query(" --query=domain",
                        "     Monitoring domain/workgroup info. ")
    print("""
                     [:::Query Example:::]
                     :Returns CRITICAL if Worgroup not empty (The server is retired from the domain).
                       --query=domain --check-one=Workgroup --critical-str=Empty-item
                     :Predefined check in the script if I only use --query=
                       --query=domain --services="Domain,DomainRole,Workgroup" --name="Domain,ServerRole,Workgroup"
                            --no-perfdata

. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .\
""")

    bcolors.title_query(" --query=timezone",
                        "   Windows time zone monitoring. ")
    print("""
                     [:::Query Example:::]
                     :Returns CRITICAL if the return data does not contain the word Prague.
                       --query=timezone --critical-str="Prague" --regex-search
                     :Predefined check in the script if I only use --query=
                       --query=timezone --services="Caption" --no-perfdat --name="Time zone"

. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .\
""")

    bcolors.title_query(" --query=serial",
                        "     Information mainly about HW server S/N, Bios version, Manufactuer etc. ")
    print("""
                     [:::Query Example:::]
                     :Predefined check in the script if I only use --query=
                       --query=serial --services="SerialNumber,ReleaseDate,Name,Manufacturer,BIOSVersion" --no-perfdata
                            --name="Serial Number,BIOS Date,BIOS Name,Manufacturer,BIOS Version"

. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .\
""")

    bcolors.title_query(" --query=hwinfo",
                        "     Information mainly about HW server Manufactuer, CPU, Memory, Model, if virtual. "
                        "I had a problem\n                     with Lenovo/IBM servers, it is necessary to remove "
                        "the SystemSKUNumber")
    print("""
                     [:::Query Example:::]
                     :Predefined check in the script if I only use --query=
                       --query=hwinfo --services="Model,Manufacturer,NumberOfProcessors,NumberOfLogicalProcessors,
                            TotalPhysicalMemory,SystemSKUNumber,HypervisorPresent" --no-perfdata --name="Model,
                            Manufacturer,Processors,Processors(Logical),PhysicalMemory,Manufacturer code,Virtual"

. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .\
""")

    bcolors.title_query(" --query=wql",
                        "        The best for the end. It is possible to define your own WQL query and your own "
                        "namespace. It is\n                     possible to monitor any WMI item there :) Unfortunately"
                        " with wmic_server, I could not define\n                     the namespace to the third and "
                        "next level (example: \ROOT\Microsoft\PolicyPlatform\Documents)")
    print("""
  -q, --wql=         Defining wql queries. If you use debug "-d" for any query under the "WMI Query" item, the used WQL
                     will be displayed. More information for example.
                     "https://learn.microsoft.com/en-us/windows/win32/wmisdk/wql-sql-for-wmi". Elevated privilege is
                     required for some queries. If you need to use '\\\\' use '\\\\\\\\'. More information about WMI
                     use '--query=wql --list-services'
  -a, --namespace=   Defining a custom WMI Namespace for example: '--namespace="root/cimv2"'. If not defined defaults
                     to "root/cimv2". Attention for wmic_server I can't enter the namespace in the third and next level.

                     [:::Query Example:::]
                     :DNS cache information
                       --query=wql --wql='SELECT * FROM MSFT_DNSClientCache' --namespace=root/StandardCimv2
                            --service="Name,Data,TimeToLive"

                     :Shows all services from 'Win32_PhysicalMemory' about 'Physical Memory 0'.
                       --query=wql --wql="SELECT * FROM Win32_PhysicalMemory WHERE Tag='Physical Memory 0'" -p

                     :Displays data from the Capacity service.
                       --query=wql --wql="SELECT * FROM Win32_PhysicalMemory WHERE Tag='Physical Memory 0'"
                            --service=Capacity

                     :If you have a physical server, it displays interesting information about DIMM/MEMORY
                       --query=wql --wql="SELECT * FROM Win32_PhysicalMemory"
                            --service="Name,Manufacturer,Speed,Capacity,ConfiguredClockSpeed"

                     :Informafion about logicak disk C:.
                       --query=wql --namespace="root/cimv2" --wql="SELECT * FROM Win32_LogicalDisk WHERE DeviceID='C:'"
                            --print-wmi
                     :Warning if there will be free space on logical disk C: between 0-80 GB Nagios
                      example (10: < 10, (outside {10 .. ∞}).
                       --query=wql --namespace="root/cimv2" --wql="SELECT * FROM Win32_LogicalDisk WHERE DeviceID='C:'"
                            --service=FreeSpace,Size --check-one=FreeSpace --human-readable=GB
                            --name="FreeSpace(GB),Size" --warning=80:

                     : Monitors FreeSpace on all volumes except 'G:' CD-ROM. It will also display additional information
                     FreeSpace,Size,VolumeName,DeviceID. Both Warning and Critical set to free space in GB.
                       --query=wql --args-ini=wql01 --warning=4.9: --critical=3.2:

                     : Show disc type MBR/GPT. I use Virtualization-based Security + TPM when migrating to VMware VMs.
                       --query=wql --args-ini=wql02

                     : Check if there is a process named 'sqlservr.exe'. If found, SQL server is installed
                     --query=wql --args-ini=wql03

                    : Check Windows Share.
                     --query=wql --args-ini=wql04

                     : Check the defined Windows service. Monitoring Ruinning/Stopped.
                       --query=wql --args-ini=wql05 --critical-str=Running

                     : An interesting data source is Win32_PerfRawData********. Here is an example of the number of
                       TCPv4 Established sessions.
                       --query=wql --args-ini=wql07

                      : Monitoring of installed applications. Idealfor Antivirus and its version.
                      --query=wql --args-ini=wql08
. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .\
\nEnd of help :)
""")


# [:::version:::] function for version of script ::::::::::::::::::::::::::::::
def f_version():
    """Print version of script"""
    print(
        '(GNU) ' + name_of_script + '  ver: ' + script_version +
        ', last modification: ' + last_modify + '\n' + '\n' +
        'Author:     ' + script_author + '\n' +
        'Script url: ' + script_github
    )


# ARGUMENTS MENU ==============================================================
# if not define arguments
if len(sys.argv[1:]) == 0:
    f_help_short()
    sys.exit(stdout_unknown)

# extension argumeents from ini file
ini_section = menu_args_ini()
if ini_section:
    ini_options = args_from_ini_load_opt(ini_section)
    for valuemenu in ini_options:
        items = args_from_ini_items(ini_section, valuemenu)
        sys.argv.extend([f"{items}"])

try:
    options, remainder = getopt.getopt(
        sys.argv[1:],
        'hU:T:H:A:t:dVq:lps:k:bn:u:ey:z:x:NQD:L:w:c:W:C:rgifmb:a:',
        ['help',
         'user=',
         'token=',
         'host=',
         'url=',
         'timeout=',
         'debug',
         'version',
         'query=',
         'list-services',
         'print-wmidata',
         'services=',
         'check-one=',
         'name=',
         'unitperf=',
         'no-perfdata',
         'no-extdata',
         'msg-desc=',
         'msg-desc-ext=',
         'args-ini=',
         'null',
         'null-output',
         'datetime=',
         'human-readable=',
         'count',
         'warning=',
         'critical=',
         'warning-str=',
         'critical-str=',
         'regex-fullmatch',
         'regex-search',
         'invert',
         'one-found',
         'multi',
         'wql=',
         'namespace=',
         'logfile=',
         'loglevel=',
         'timeback=',
         'eventid=',
         'eventsource=',
         'eventcategory=',
         'eventmsg=',
         'event-not=',
         'xxx=',
         ])

except getopt.GetoptError as err:
    print('ERROR:', err)
    sys.exit(stdout_unknown)

for opt, arg in options:
    if opt in ('-h', '--help'):
        f_help_full()
        sys.exit()
    elif opt in ('-U', '--user'):
        args_userid = arg
    elif opt in ('-T', '--token'):
        args_token = arg
    elif opt in ('-H', '--host'):
        args_host = arg
    elif opt in ('-A', '--url'):
        wmi_server_url = arg
    elif opt in ('-t', '--timeout'):
        requests_timeout = int(arg)
    elif opt in ('-d', '--debug'):
        args_debug = True
    elif opt in ('-V', '--version'):
        f_version()
        sys.exit()

# :::monitoring options:::
    elif opt in ('-q', '--query'):
        args_query = arg
    elif opt in ('-l', '--list-services'):
        args_list_services = True
    elif opt in ('-p', '--print-wmidata'):
        args_print_wmidata = True
    elif opt in ('-s', '--services'):
        args_services = arg
    elif opt in ('-k', '--check-one'):
        args_check_one = arg
    elif opt in ('-n', '--name'):
        args_name = arg
    elif opt in ('-u', '--unitperf'):
        args_unitperf = arg
    elif opt in ('-e', '--no-perfdata'):
        args_no_perfdata = True
    elif opt in ('-j', '--no-extdata'):
        args_no_extdata = True
    elif opt in ('-y', '--msg-desc'):
        args_msg_desc = arg
    elif opt in ('-z', '--msg-desc-ext'):
        args_msg_desc_ext = arg
    elif opt in ('-w', '--warning'):
        args_warning = arg
    elif opt in ('-x', '--args-ini'):
        args_args_ini = arg
    elif opt in ('-N', '--null'):
        args_null = True
    elif opt in ('-Q', '--null-output'):
        args_null_output = True
    elif opt in ('-D', '--datetime'):
        args_datetime = arg
    elif opt in ('-L', '--human-readable'):
        args_human_readable = arg
    elif opt in ('-b', '--count'):
        args_count = True
    elif opt in ('-c', '--critical'):
        args_critical = arg
    elif opt in ('-W', '--warning-str'):
        args_warning_str = arg
    elif opt in ('-C', '--critical-str'):
        args_critical_str = arg
    elif opt in ('-r', '--regex-fullmatch'):
        args_reqex_full = True
    elif opt in ('-g', '--regex-search'):
        args_reqex_search = True
    elif opt in ('-i', '--invert'):
        args_invert = True
    elif opt in ('-f', '--one-found'):
        args_one_found = True
    elif opt in ('-m', '--multi'):
        args_multi = True
    elif opt in ('--wql'):
        args_wql = arg
    elif opt in ('--namespace'):
        args_namespace = arg
    elif opt in ('--logfile'):
        args_logfile = arg
    elif opt in ('--loglevel'):
        args_loglevel = arg
    elif opt in ('--timeback'):
        args_timeback = arg
    elif opt in ('--eventid'):
        args_eventid = arg
    elif opt in ('--eventsource'):
        args_eventsource = arg
    elif opt in ('--eventcategory'):
        args_eventcategory = arg
    elif opt in ('--eventmsg'):
        args_eventmsg = arg
    elif opt in ('--event-not='):
        args_event_not = arg
    elif opt in ('--xxx'):
        args_xxx = arg

dbg_separator("DEBUG ALL ARGUMENTS")
# debug print arguments
dbg('Arguments\t\t\t', options)

# debug print arguments02
dbg('Arguments --debug\t\t', args_debug)

# debug arguments
dbg('Arguments --list-services\t', args_list_services)
dbg('Arguments --print-wmidata\t', args_print_wmidata)
dbg('Arguments --services=\t\t', args_services)
dbg('Arguments --check-one\t\t', args_check_one)
dbg('Arguments --name=\t\t', args_name)
dbg('Arguments --unitperf=\t\t', args_unitperf)
dbg('Arguments --no-perfdata\t\t', args_no_perfdata)
dbg('Arguments --no-extdata\t\t', args_no_extdata)
dbg('Arguments --msg-desc=\t\t', args_msg_desc)
dbg('Arguments --msg-desc-ext=\t', args_msg_desc_ext)
dbg('Arguments --args-ini=\t\t', args_args_ini)
dbg('Arguments --null\t\t', args_null)
dbg('Arguments --null-output\t\t', args_null_output)
dbg('Arguments --datetime=\t\t', args_datetime)
dbg('Arguments --human_readable\t', args_human_readable)
dbg('Arguments --count\t\t', args_count)
dbg('Arguments --warning=\t\t', args_warning)
dbg('Arguments --critical=\t\t', args_critical)
dbg('Arguments --warning-str=\t', args_warning_str)
dbg('Arguments --critical-str=\t', args_critical_str)
dbg('Arguments --regex-fullmatch\t', args_reqex_full)
dbg('Arguments --regex-search\t', args_reqex_search)
dbg('Arguments --invert\t\t', args_invert)
dbg('Arguments --one-found\t\t', args_one_found)
dbg('Arguments --multi\t\t', args_multi)
dbg('Arguments --wql=\t\t', args_wql)
dbg('Arguments --namespace=\t\t', args_namespace)
dbg('Arguments --logfile=\t\t', args_logfile)
dbg('Arguments --loglevel=\t\t', args_loglevel)
dbg('Arguments --timeback=\t\t', args_timeback)
dbg('Arguments --eventid=\t\t', args_eventid)
dbg('Arguments --eventsource=\t', args_eventsource)
dbg('Arguments --eventcategory=\t', args_eventcategory)
dbg('Arguments --eventmsg=\t\t', args_eventmsg)
dbg('Arguments --event-not=\t\t', args_event_not)
dbg('Arguments --xxx\t\t\t', args_xxx)
dbg_separator("PRINT ALL VARIABLE & FUNCTION")


# CHECK MENU - MANDATORY PARAMETERS ###########################################
if args_userid == 'None':
    f_help_short()
    sys.exit()
elif args_token == 'None':
    f_help_short()
    sys.exit()
elif args_host == 'None':
    f_help_short()
    sys.exit()
elif args_query == 'None':
    f_help_short()
    sys.exit()


# CHECK MENU - NULL PARAMETERS ################################################
if args_warning == "":
    bcolors.fail("[ERROR] The parameter '--warning' is empty.")
    sys.exit(stdout_critical)

if args_critical == "":
    bcolors.fail("[ERROR] The parameter '--critical' is empty.")
    sys.exit(stdout_critical)

if args_warning_str == "":
    bcolors.fail("[ERROR] The parameter '--warning-str' is empty.")
    sys.exit(stdout_critical)

if args_critical_str == "":
    bcolors.fail("[ERROR] The parameter '--critical-str' is empty.")
    sys.exit(stdout_critical)


# CHECK MENU - COMBING PARAMETERS #############################################
# mesage = ("[ERROR] It is not possible to combine these two arguments " +
#           "( '--multi' and '--one-found' ).")

# if args_multi and args_one_found:
#     bcolors.fail(mesage)
#     sys.exit(stdout_critical)

mesage = ("[ERROR] It is not possible to combine '--warning' or " +
          "'--critical' with '--warning-str' or '--critical-str'.")

if args_warning_str or args_critical_str or args_warning or args_critical:
    if args_warning_str and args_critical:
        bcolors.fail(mesage)
        sys.exit(stdout_critical)
    elif args_critical_str and args_warning:
        bcolors.fail(mesage)
        sys.exit(stdout_critical)
    elif args_warning_str and args_warning:
        bcolors.fail(mesage)
        sys.exit(stdout_critical)
    elif args_critical_str and args_critical:
        bcolors.fail(mesage)
        sys.exit(stdout_critical)

mesage = ("[ERROR] It is not possible to combine '--warning' or '--critical' " +
          "with parameters for '--warning-str' or '--critical-str' " +
          "(--regex-full, --regex-search, --invert, --one-found).")

if (args_warning or args_critical) and (
    args_reqex_full or args_reqex_search or args_invert
):
    bcolors.fail(mesage)
    sys.exit(stdout_critical)
elif (args_warning or args_critical) and (args_one_found or args_multi):
    bcolors.fail(mesage)
    sys.exit(stdout_critical)


# CHECK MENU - NUMBER OF PARAMETERS ###########################################
control_list = []

if args_check_one:
    control_list = args_check_one.split(',')
    if len(control_list) > 1:
        bcolors.fail("[ERROR] Only one service can be selected for the " +
                     "--check-one parameter")
        control_list = []
        sys.exit(stdout_critical)


# FUNCTION [03] - WMIC ========================================================
# [:::HTTP to wmic:::] function for HTTP request to wmic_server :::::::::::::::
def f_http_get_wmi(wmi_name_space, wmi_query):
    """For HTTP/HTTPS request to wmic_server for wmi data"""

    try:
        headers = {"Content-type": "application/json"}
        data_reg = {"id": args_userid,
                    "token": args_token,
                    "host": args_host,
                    "query": wmi_query,
                    "namespace": wmi_name_space}

        data = requests.post(wmi_server_url, data=json.dumps(data_reg),
                             headers=headers, timeout=requests_timeout)

    except (TimeoutError, requests.exceptions.ConnectTimeout,
            requests.exceptions.ReadTimeout,
            requests.exceptions.ConnectionError) as error:

        msg = (f"[ERROR {type(error).__name__}] "
               f"HTTP Connection fail to host: '{args_host}'. Max retries "
               f"exceeded timeout: '{requests_timeout}' sec. with wmic_server "
               f"url: '{wmi_server_url}'. Failed to "
               "establish a new connection. Most likely the wrong IP address "
               "of wmic_server or the server is unavailable.")

        nagios_unknown(msg)
        sys.exit(stdout_unknown)

    # extent post info
    # print(data.raise_for_status())
    # print(data.url)
    # print(data.close)
    # print(data.connection)
    # print(data.content)
    # print(data.cookies)
    # print(data.elapsed)
    # print(data.encoding)
    # print(data.headers)
    # print(data.history)
    # print(data.is_permanent_redirect)
    # print(data.is_redirect)
    # print(data.iter_content)
    # print(data.iter_lines)
    # print(data.json)
    # print(data.links)
    # print(data.next)
    # print(data.ok)
    # print(data.raise_for_status)
    # print(data.raw)
    # print(data.reason)
    # print(data.request)
    # print(data.status_code)
    # print(data.text)
    # print(data.headers['Content-Length'])

    content_length = int(data.headers['Content-Length'])

    if args_query == 'eventlog' and content_length <= 2:
        dbg("HTTP/WMI 'data.status_code'\t", data.status_code)
        dbg("HTTP/WMI 'Content-Length'\t", content_length)
        data_in_list = f_eventlog_wmi_null()
        dbg("HTTP/WWI 'merge_keys_data'\t", data_in_list)
        dbg_separator("LIST/DICTIONARY")
        return f_eventlog_wmi_found(data_in_list)
    else:
        try:
            dbg("HTTP/WMI 'data.status_code'\t", data.status_code)
            dbg("HTTP/WMI 'Content-Length'\t", content_length)
            data_in_list = data.json()
            merge_keys_data = f_wmic_data_merge_keys(data_in_list)

            if args_query == 'eventlog':
                merge_keys_data = f_eventlog_wmi_found(merge_keys_data)

            dbg("HTTP/WWI 'merge_keys_data'\t", merge_keys_data)
            dbg_separator("LIST/DICTIONARY")
            return merge_keys_data
        except json.decoder.JSONDecodeError as error:
            msg = (f"[ERROR {type(error).__name__}] "
                   "wmic_server problem no data returned. Possible causes: "
                   "wrong WMI WQL query, incorrectly entered CLI, short "
                   "timeout etc.")
            nagios_unknown(msg)
            sys.exit(stdout_unknown)


def f_eventlog_wmi_null():
    """ Function for eventlog add null data"""

    l = {"RecordNumber": 0, "Logfile": args_logfile, "EventIdentifier": 0,
         "EventCode": 0, "SourceName": "Null", "Type": "Null", "Category": 0,
         "CategoryString": 0, "TimeGenerated": 0, "TimeWritten": 0,
         "ComputerName": "Null", "User": "Null", "Message": "Null", "InsertionStrings": 0,
         "Data": "Null", "EventType": 0, "Found": 0}
    return l


def f_eventlog_wmi_found(data):
    """ Function for eventlog add to Found to data"""

    for k, v in data.items():
        if isinstance(data[k], list):
            number = len(v)
        else:
            if (v == 0) or (k == "Null"):
                number = int(0)
            else:
                number = int(1)
        break

    # add found key and value
    data["Found"] = (number)
    return data


# [::: wmic_data merging duplicate keys:::] :::::::::::::::::::::::::::::::::::
# thank you :
# https://stackoverflow.com/questions/14902299/json-loads-allows-duplicate-\
# keys-in-a-dictionary-overwriting-the-first-value
# https://www.geeksforgeeks.org/python-merge-dictionaries-list-with-duplicate-\
# keys/
def f_wmic_data_merge_keys(data_in_list):
    """ Merging duplicate keys for wmi data """
    d = {}
    for idx in range(0, len(data_in_list)):
        # getting keys of corresponding index
        for k in data_in_list[idx]:
            v = data_in_list[idx][k]
            # if it is already a duplicate key, it will extend the value by
            # the value from the duplicate key
            if k in d:
                if isinstance(d[k], list):
                    if isinstance(v, list):
                        d[k].extend(v)
                    else:
                        d[k].append(v)
                else:
                    d[k] = [d[k]]
                    d[k].append(v)
            else:
                d[k] = v
    return d


# FUNCTION [04] - NAGIOS MESSAGE ==============================================
# [:::NAGIOS message and return code:::] ::::::::::::::::::::::::::::::::::::::
# OK
def nagios_ok(msg: str) -> None:
    """Function for Nagios output"""

    if args_null_output:
        events_found = ""
        events_found = len(return_data_list)
        print(f"OK:{args_msg_desc}"
              f" Found: '{events_found}' item(s)|{perfdata}"
              f"{nagios_remove_char(extend_data)}")
        sys.exit(0)

    print(f"OK:{args_msg_desc}{msg[:-1]}|{perfdata}"
          f"{nagios_remove_char(extend_data)}")
    sys.exit(0)


# WARNING
def nagios_warning(msg: str) -> None:
    """Function for Nagios output"""

    if args_null_output:
        print(f"WARNING:{args_msg_desc}"
              f" Threshold found: '{event_found}' item(s)|{perfdata}"
              f"\n{f_msg_desc_ext(args_msg_desc_ext)}"
              f"{nagios_remove_char(extend_data)}")
        sys.exit(1)

    print(f"WARNING:{args_msg_desc} Threshold found: '{event_found}' item(s)"
          f" -{msg[:-1]}|{perfdata}"
          f"\n{f_msg_desc_ext(args_msg_desc_ext)}"
          f"{nagios_remove_char(extend_data)}")
    sys.exit(1)


# CRITICAL
def nagios_critical(msg: str) -> None:
    """Function for Nagios output"""

    if args_null_output:
        print(f"CRITICAL:{args_msg_desc}"
              f" Threshold found: '{event_found}' item(s)|{perfdata}"
              f"\n{f_msg_desc_ext(args_msg_desc_ext)}"
              f"{nagios_remove_char(extend_data)}")
        sys.exit(2)

    print(f"CRITICAL:{args_msg_desc} Threshold found: '{event_found}' item(s)"
          f" -{msg[:-1]}|{perfdata}"
          f"\n{f_msg_desc_ext(args_msg_desc_ext)}"
          f"{nagios_remove_char(extend_data)}")
    sys.exit(2)


def nagios_unknown(msg: str) -> None:
    """Function for Nagios output"""

    print(f"UNKONWN: {msg}|{perfdata}{nagios_remove_char(extend_data)}")
    sys.exit(3)


def nagios_remove_char(msg):
    """Function remove charset from text"""

    msg_replace = msg.replace('\\r', '')
    msg_replace = msg_replace.replace('\\n', ' ')
    msg_replace = msg_replace.replace('\\t', ' ')

    return msg_replace


# FUNCTION [05] - LIST SERVICE ================================================
# [:::--list-services :::] ::::::::::::::::::::::::::::::::::::::::::::::::::::
def f_list_services(query, url, wmi_class, namespace):
    """ Function for list all possible services"""

    print(bcolors.W + "LIST OF ALL POSSIBLE SERVICES TO MONITORING " +
          "[--query=" + query + "]" + "\n" + bcolors.ENDC)

    msg = ("1. To view all possible monitoring services, visit this website:" +
           "\n   " + bcolors.W + url + bcolors.ENDC + "\n\n"
           "2. On the Microsoft web page is list of all possible services " +
           "for:\n"
           "   WMI Namespaces:\t" + bcolors.W + namespace + "\n" +
           bcolors.ENDC +
           "   WMI_Class:\t\t" + bcolors.W + wmi_class + bcolors.ENDC + "\n" +
           "  \n   The meanings of individual services and their data types " +
           "are explained here." + "\n\n" +
           "3. If you use the parameter " + bcolors.W + "'--query=" +
           query + " --print-wmidata'" +
           bcolors.ENDC + " " + name_of_script +
           " will return\n   all services and data for the corresponding " +
           "WMI class.\n\n")

    print(msg)

    print("4. For your own research, it is ideal to use this program on "
          "Windows and find\n   the necessary WMI Classes. "
          "\n   WMI Explorer 2.x : https://github.com/vinaypamnani/wmie2/"
          "releases")

    print("""
    ---------------------------------------------------------------------------
    Data Types in WMI
    ---------------------------------------------------------------------------
    string  : Text
    boolean : True/False
    datetime: Date and time, or time interval
    sint8   : Signed  8-Bit Integer   - Numberr [0 to 255]
    sint16  : Signed 16-Bit Integer   - Number [0 to 65,535]
    sint32  : Signed 32-Bit Integer   - Number [0 to 4,294,967,295]
    sint64  : Signed 64-Bit Integer   - Number [0 to 18,446,744,073,709,551,615]
    uint8   : Unsigned  8-Bit Integer - Number [0 to 255]
    uint16  : Unsigned 16-Bit Integer - Number [0 to 65,535]
    uint32  : Unsigned 32-Bit Integer - Number [0 to 4,294,967,295]
    uint64  : Unsigned 64-Bit Integer - Number [0 to 18,446,744,073,709,551,615]


    ---------------------------------------------------------------------------
    WMI Structure:
    ---------------------------------------------------------------------------
    Namespace   Example: root\cimv2
    Classes     Example: Win32_NetworkAdapterConfiguration
    Instances   Example: Index=1
    Propertis   Example: IPAddress,MACAddress


        WMI WQL:
        'https://learn.microsoft.com/en-us/windows/win32/wmisdk/wql-sql-for-wmi'
        -----------------------------------------------------------------------

        [Example WMI for WQL:]
        "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE Index=1"

        [WMI path:]
        \\\COMPUTER-NAME\ROOT\cimv2:Win32_NetworkAdapterConfiguration.Index=1

        [WMI Data:]
        instance of Win32_NetworkAdapterConfiguration
        {
            Caption = "[00000001] vmxnet3 Ethernet Adapter";
            DatabasePath = "%SystemRoot%\\System32\\drivers\\etc";
            DefaultIPGateway = {"10.115.120.1"};
            Description = "vmxnet3 Ethernet Adapter";
            DHCPEnabled = FALSE;
            DNSDomainSuffixSearchOrder = {"root.domain.com"};
            DNSEnabledForWINSResolution = FALSE;
            DNSHostName = "COMPUTER-NAME";
            DNSServerSearchOrder = {"10.115.120.242", "10.115.120.243"};
            DomainDNSRegistrationEnabled = FALSE;
            FullDNSRegistrationEnabled = FALSE;
            ...
    """)
    sys.exit()


# FUNCTION [06] - ADD TO LIST  ================================================
def f_args_parameters_add_to_list():
    """Function create list from arguments"""
    global services_list, threshold_list, name_list

    if args_services and args_check_one:
        global services_list_cho
        services_list = f_add_args_list(args_check_one,
                                        name_of_list="services_list",
                                        text="--services", tab="\t")
        services_list_cho = f_add_args_list(args_services,
                                            name_of_list="services_list_cho",
                                            text="--check-one", tab="")

    if args_services and not args_check_one:
        services_list = f_add_args_list(args_services,
                                        name_of_list="services_list",
                                        text="--services", tab="\t")

    if args_name:
        name_list = f_add_args_list(args_name,
                                    name_of_list="name_list",
                                    text="--name\t", tab="\t")
        if not args_check_one:
            if len(name_list) != len(services_list):
                f_check_number_of_parameters(name="--name")
        elif args_check_one:
            if len(name_list) != len(services_list_cho):
                f_check_number_of_parameters(name="--name")

    if args_unitperf:
        global unit_perf_list
        unit_perf_list = f_add_args_list(args_unitperf,
                                         name_of_list="unit_perf_list",
                                         text="--unitperf", tab="")
        if len(unit_perf_list) != len(services_list):
            f_check_number_of_parameters(name="--unitperf")

    if args_warning or args_critical:
        threshold_list = f_threshold_to_list(args_warning, args_critical)

    if args_warning_str or args_critical_str:
        threshold_list = f_threshold_to_list(args_warning_str, args_critical_str)


# :::[ add arguments to list] :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
def f_add_args_list(args, name_of_list, text, tab):
    """Function services add to list and print debug"""
    l = args.split(',')
    dbg(text + '\t\'' + name_of_list + '\'' + tab, l)
    return l


# :::[--warning= and --critical= add to list] :::::::::::::::::::::::::::::::::
def f_threshold_to_list(warning, critical):
    """Function --warning and --critical add to list"""
    l = []

    if warning and critical:
        l = []
        l.append(warning)
        l.append(critical)

    elif warning:
        l = []
        l.append(warning)
        l.append("")

    elif critical:
        l = []
        l.append("")
        l.append(critical)

    dbg('-w/-W & -c/-C\t\'threshold_list\'', l)
    return l


# ::: return only data from services to list ::::::::::::::::::::::::::::::::::
def f_returned_list(data):
    """Function return data from services to list"""

    msg = ("[ERROR05] KeyError - Service name is not entered correctly. Pay " +
           "attention to the capitalization of the letters is " +
           "case-sensitive. Use parameter " + appo + "--list-services" + appo +
           " for to list the correct names.")
    l = []
    merge_data_list = []

    try:
        for k in services_list:
            # duplicate key in wmi data. etc win32_networkadapterconfiguration
            if isinstance(data[k], list):
                l.append(data[k])
            else:
                if data[k] == "":
                    data[k] = 'Empty-item'
                    l.append(data[k])
                else:
                    l.append(data[k])
    # if error in keys
    except KeyError:
        nagios_unknown(msg)

    # to one list
    for v in l:
        if isinstance(v, list):
            merge_data_list.extend(v)
        else:
            merge_data_list.append(v)

    return merge_data_list


# FUNCTION [07] - MSG_OUTPUT ==================================================
# :::--services is define :::::::::::::::::::::::::::::::::::::::::::::::::::::
def f_services(data):
    """Function for returning values for services in wmi data to msg_output"""

    msg = ("[ERROR01] KeyError - Service name is not entered correctly. Pay " +
           "attention to the capitalization of the letters is " +
           "case-sensitive. Use parameter " + appo + "--list-services" + appo +
           " for to list the correct names.")

    output = ""

    if args_query == 'eventlog':
        return f_services_eventlog(data)

    # if args_name define
    if args_name:
        output = f_services_own_desc(data)
        return output

    try:
        if args_check_one:
            for x in services_list_cho:
                x_extend = ""
                if x == args_check_one:
                    x_extend = str("(threshold)")
                output += " " + x + x_extend + ": " + str(data[x]) + semi
            return output
        else:
            for x in services_list:
                output += " " + x + ": " + str(data[x]) + semi
            return output

    # if error in keys
    except KeyError:
        nagios_unknown(msg)

    return None


# ::: messasges fo eventlog :::::::::::::::::::::::::::::::::::::::::::::::::::
def f_services_eventlog(data):
    """Function for event log message"""

    output = ""

    if int(data["Found"]) == 0:
        output += (" Found " + appo + "0" + appo +
                   " event in the EventLog: " + str(args_logfile) + ";"
                   " Timeback: " + str(args_timeback) + ";" +
                   " Log Level: " + str(args_loglevel) + " ")
    else:
        output += (" Found " + appo + str(data["Found"]) + appo +
                   " event(s) in the EventLog: " + str(args_logfile) + ";"
                   " Timeback: " + str(args_timeback) + ";" +
                   " Log Level: " + str(args_loglevel) + " ")

    return output


# :::[--services and --name] ::::::::::::::::::::::::::::::::::::::::::::::
def f_services_own_desc(data):
    """Function for returning values for services in wmi data to msg_output
       with own description"""

    msg = ("[ERROR02] KeyError - Service name is not entered correctly. Pay " +
           "attention to the capitalization of the letters is " +
           "case-sensitive. Use parameter " + appo + "--list-services" + appo +
           " for to list the correct names.")

    output = ""

    d = name_services_dict

    try:
        for k, v in d.items():
            k_extend = ""
            if v == args_check_one:
                k_extend = str("(threshold)")
            output += " " + k + k_extend + ": " + str(data[v]) + semi
        return output

    # if error in keys
    except KeyError:
        nagios_unknown(msg)

    return None


def f_services_own_desc_01(n_list, srv_list):
    """Helper function for f_services_own_desc
       Create dictionary from data"""
    global name_services_dict

    # create dictionary from two lists
    name_services_dict = {k: v for k, v in zip(n_list, srv_list)}
    dbg('\t\t\'name_services_dict\'', name_services_dict)
    return name_services_dict


# ::: add extend data to output msg :::::::::::::::::::::::::::::::::::::::::::
def f_msg_ouput_extend(dict01):
    """Add extend data to output msg"""

    output = ""

    if args_query == 'eventlog':
        output += f_msg_ouput_extend_eventlog(dict01, output)

    if args_no_extdata:
        output = ""

    return output


def f_msg_ouput_extend_eventlog(dictionary, output):
    """Add extend data to output msg for eventlog"""

    output += (f"\n\n{window_width * '='}\n [ATTENTION!!!] - All the logs "
               "corresponding to the --query=eventlog parameters are "
               f"displayed below,\n not corresponding to the threshold "
               f"parameters!\n{window_width * '='}\n")

    l_keys = list(dictionary.keys())

    if isinstance(dictionary[l_keys[0]], list):
        value_len = len(dictionary[l_keys[0]])
    else:
        value_len = 1

    if isinstance(dictionary[l_keys[0]], list):
        i = 0
        while i <= (value_len - 1):
            # print(i)
            output += f"___Log:[{dictionary['Logfile'][i]}] "
            output += f"EventID:[{dictionary['EventCode'][i]}] "
            output += f"Date:[{dictionary['TimeWritten'][i]}] "
            output += f"Type:[{dictionary['Type'][i]}] "
            output += f"Source:[{dictionary['SourceName'][i]}] "
            output += f"TaskCategory:[{dictionary['CategoryString'][i]}] "
            message_line = {dictionary['Message'][i]}
            output += f"Message:[{message_line}] "
            output += "\n\n"
            i += 1
    else:
        output += f"___Log:[{dictionary['Logfile']}] "
        output += f"EventID:[{dictionary['EventCode']}] "
        output += f"Date:[{dictionary['TimeWritten']}] "
        output += f"Type:[{dictionary['Type']}] "
        output += f"Source:[{dictionary['SourceName']}] "
        output += f"TaskCategory:[{dictionary['CategoryString']}] "
        message_line = {dictionary['Message']}
        output += f"Message:[{message_line}] "
        output += "\n\n"

    return output


# FUNCTION [08] - ADD DICTIONARY ==============================================
# ::: return only data from services ::::::::::::::::::::::::::::::::::::::::::
def f_returned_dict(data):
    """Function data to dictionary"""

    msg = ("[ERROR03] KeyError - Service name is not entered correctly. Pay " +
           "attention to the capitalization of the letters is " +
           "case-sensitive. Use parameter " + appo + "--list-services" + appo +
           " for to list the correct names.")
    # output = ""

    d = {}
    try:
        for k in services_list:
            # duplicate key in wmi data. etc win32_networkadapterconfiguration
            if isinstance(data[k], list):
                # output = data[k]
                d[k] = data[k]
            else:
                d[k] = data[k]
        return d
    # if error in keys
    except KeyError:
        nagios_unknown(msg)
        # bcolors.fail(msg)
        # sys.exit(stdout_unknown)

    return None


# ::: make dictionary for perf data with own_desc::::::::::::::::::::::::::::::
def f_data_dict(data):
    """Function add data to dictionary."""

    msg = ("[ERROR04] KeyError - Service name is not entered correctly. Pay " +
           "attention to the capitalization of the letters is " +
           "case-sensitive. Use parameter " + appo + "--list-services" + appo +
           " for to list the correct names.")

    if args_name and args_check_one:
        d = {}
        l = []
        for k, v in name_services_dict.items():
            if v == args_check_one:
                l.append(k)
        d = {k: data[v] for k, v in zip(l, services_list)}
        return d
    elif args_name and not args_check_one:
        d = {}
        try:
            for v in services_list:
                # for k in name_list:
                # duplicate key in wmi data. etc
                # win32_networkadapterconfiguration
                if isinstance(data[v], list):
                    d = {k: data[v] for k, v in zip(name_list, services_list)}
                else:
                    d = {k: data[v] for k, v in zip(name_list, services_list)}
            return d
        except KeyError:
            nagios_unknown(msg)
            # bcolors.fail(msg)
            # sys.exit(stdout_unknown)
    else:
        dictionary = copy.copy(return_data_dict)
        return dictionary

    return None


# ::: add perfdata and unit to dictionary :::::::::::::::::::::::::::::::::::::
def f_check_number_of_parameters(name):
    """Function show error message when if a different number of
    arguments is specified"""

    msg = ("[ERROR] The number of parameters in '--services=' or " +
           "'--check-one=' is diferent then" + appo + name + "='. " +
           "For a multiple check the number must be the same.")

    nagios_unknown(msg)
    sys.exit(stdout_unknown)


# FUNCTION [08] - PERFDATA DICT ===============================================
# ::: add perfdta and unit to dictionary ::::::::::::::::::::::::::::::::::::::
def f_perfdata_to_dict(data_dictionary):
    """ Function create perfdata dictionary with possible define unit.
        Only numbers are added to the dictionary """
    # clone list
    unit_perf_list_copy = copy.copy(unit_perf_list)
    # perf_list = []
    perf_dict = {}

    # if define own units. Add to dictionary only number
    if unit_perf_list:
        perf_dict = f_perfdata_to_dict__sub03(data_dictionary,
                                              unit_perf_list_copy)
    else:
        # if not isinstance(v, list):
        for k, v in data_dictionary.items():

            if isinstance(v, list):
                # cuting list and check if number
                list_only_number = f_perfdata_to_dict__cutting_value(v)
                if list_only_number:
                    perf_dict[k] = list_only_number

            else:
                if f_check_if_number(v):
                    perf_dict[k] = str(v)

    return perf_dict


def f_perfdata_to_dict__sub01(unit_perf_list_copy, v):
    """ Help function for "f_perfdata_to_dict"
    Is perfdata list then adds unit to individual list items"""
    # cating the list
    for unit in unit_perf_list_copy:
        unit_perf_list_copy.remove(unit)
        unit_value = f_perfdata_to_dict__sub02(v, unit)
        break
    return unit_value


def f_perfdata_to_dict__sub02(value_in_list, unit):
    """ Helper function for "f_perfdata_to_dict"
    Check is number and add unit to value """
    l = []
    for v in value_in_list:
        if f_check_if_number(v):
            l.append(str(v) + str(unit))
    if l:
        return l
    return None


def f_perfdata_to_dict__sub03(data_dictionary, unit_perf_list_copy):
    """ Helper function for "f_perfdata_to_dict"
    Ff define own units. Add to dictionary only number"""

    perf_dict = {}

    for k, v in data_dictionary.items():

        # for multi-item in list [15, 25, 25]
        if not isinstance(v, list):
            for unit in unit_perf_list_copy:
                if f_check_if_number(v):
                    perf_dict[k] = str(v) + str(unit)
                    unit_perf_list_copy.remove(unit)
                else:
                    unit_perf_list_copy.remove(unit)
                break
        else:
            # value is list [15, 25, 25]
            list_with_unit = f_perfdata_to_dict__sub01(
                                                unit_perf_list_copy, v)
            if list_with_unit:
                perf_dict[k] = list_with_unit

    return perf_dict


def f_perfdata_to_dict__cutting_value(value_in_list):
    """ Helper function for "f_perfdata_to_dict"
    Cuting value in list and check is number"""
    l = []
    for v in value_in_list:
        if f_check_if_number(v):
            l.append(str(v))
    if l:
        return l
    return None


# FUNCTION [09] - PERFDATA + WARNING/CRITICAL =================================
# ::: function perfdata :::::::::::::::::::::::::::::::::::::::::::::::::::::::
def f_perfdata(warning, critical, dictionary):
    """ Function return perfdata
    'label'=value[UOM];[warn];[crit];[min];[max] """
    output = ""
    index = 1

    # --no-perfdata
    if args_no_perfdata:
        return ""

    # perfdata is not number. perfdata_dict is empty
    if not dictionary:
        return output

    # if warning or critical
    if warning or critical:
        f_treshold_corect(warning)
        f_treshold_corect(critical)
        output = f_perfdata_sub02(dictionary, warning, critical, index)

    # without warning or critical
    else:
        for k, v in dictionary.items():
            if isinstance(v, list):
                for value in v:
                    output += (appo + str(k) + "_" + str(index) + appo +
                               "=" + str(value) + ";;;;" + " ")
                    if index == len(v):
                        index = 0
                    index = int(index) + 1
                # return str(output)
            else:
                output += str(appo + k + appo + "=" + v + ";;;;" + " ")
        # return str(output)
    return str(output)


def f_perfdata_sub01(threshold):
    """ Helper function for f_perfdata
    Function return treshold for perfdata"""

    # return if not set threshold
    if not threshold:
        return ""

    threshold = str(threshold)

    # a)
    if f_check_if_number(threshold):
        return threshold
    else:
        return f_perfdata_sub01_01(threshold)


def f_perfdata_sub01_01(threshold):
    """ Helper function for f_perfdata_sub01
    Return threshold"""

    l = []

    l = threshold.split(':')
    # b)
    if l[1] == "":
        return l[0]
    # c)
    elif l[0] == "~":
        return l[1]
    # d)
    elif f_check_if_number(l[0]) and f_check_if_number(l[1]):
        return l[1]
    # e) must be after d)
    elif l[0][0] == "@":
        l_new = []
        for v in l:
            v = v.replace("@", "")
            l_new.append(v)
        l = l_new
        return l[1]
    return None


def f_perfdata_sub02(dictionary, warning, critical, index):
    """ Helper function for f_perfdata
    Function return treshold for perfdata"""

    output = ""

    for k, v in dictionary.items():
        if isinstance(v, list):
            for value in v:
                output += (appo + str(k) + "_" + str(index) + appo +
                           "=" + str(value) + ";" +
                           str(f_perfdata_sub01(warning)) + ";" +
                           str(f_perfdata_sub01(critical)) + ";" +
                           ";" + " ")
                if index == len(v):
                    index = 0
                index = int(index) + 1
            # return str(output)
        else:
            output += str(appo + k + appo + "=" + v + ";" +
                          str(f_perfdata_sub01(warning)) + ";" +
                          str(f_perfdata_sub01(critical)) + ";" +
                          ";" + " ")
    return str(output)


# FUNCTION [10] - ADD TO DICTIONARY ===========================================
def f_args_add_to_dictionary():
    """Helper function for f_services_own_desc
       Create dictionary from data"""
    global name_services_dict

    if args_check_one:
        # create dictionary from two lists
        name_services_dict = {k: v for k, v in zip(name_list,
                              services_list_cho)}
        dbg('\t\t\'name_services_dict\'', name_services_dict)
        return name_services_dict
        # d = f_services_own_desc_01(name_list, services_list_cho)
    else:
        # create dictionary from two lists
        name_services_dict = {k: v for k, v in zip(name_list, services_list)}
        dbg('\t\t\'name_services_dict\'', name_services_dict)
        return name_services_dict
        # d = f_services_own_desc_01(name_list, services_list)


# FUNCTION [11] - WARNING/CRITICAL NUMBER =====================================
# ::: function WARNING/CRITICAL :::::::::::::::::::::::::::::::::::::::::::::::
def f_thresholds_check(warning, critical, data_list):
    """ Functions for complete evaluation of WARNING/CRITICAL (is number)"""

    if args_count:
        data_list = f_thresholds_count(data_list)

    if warning and critical:
        if f_thresholds_check_sub01(critical, data_list):
            nagios_critical(msg_output)
        elif f_thresholds_check_sub01(warning, data_list):
            nagios_warning(msg_output)
        else:
            nagios_ok(msg_output)
    elif critical:
        if f_thresholds_check_sub01(critical, data_list):
            nagios_critical(msg_output)
        else:
            nagios_ok(msg_output)
    elif warning:
        if f_thresholds_check_sub01(warning, data_list):
            nagios_warning(msg_output)
        else:
            nagios_ok(msg_output)


def f_thresholds_check_sub01(threshold, data_list):
    """Helper function for f_thresholds_check
    cutting when data_list list"""

    global event_found

    # list for boolean
    l = []

    for value in data_list:
        if isinstance(value, list):
            data_list_copy = copy.copy(value)
            for v in data_list_copy:
                f_thresholds_check_sub04(v)
                return_data = float(v)
                # create list with boolean threshold evaluation
                l.append(f_thresholds_check_sub03(threshold, return_data))
        else:
            f_thresholds_check_sub04(value)
            return_data = float(value)
            # create list with boolean threshold evaluation
            l.append(f_thresholds_check_sub03(threshold, return_data))

    # if boolean True in list is at least one value warning or critical
    dbg("thresholds: " + "\t\t\t", str(threshold))
    dbg("Compare thresholds with return_data:", str(l))

    # summary True in list. Use for eventlog
    if args_count:
        pass
    else:
        event_found = f_thresholds_check_summary(l)

    # final evaluation list
    if True in l:
        bool_return = True
        return bool_return
    else:
        return False


def f_thresholds_check_sub03(threshold: str, return_data):
    """Helper function for f_thresholds_check_sub01.
    Function detect nagios threshold type

    Range       Generate an alert if x...
    -------------------------------------------------------------
    a) 10       < 0 or > 10     (outside the range of {0 .. 10})
    b) 10:      < 10            (outside {10 .. ∞})
    c) ~:10     > 10            (outside the range of {-∞ .. 10})
    d) 10:20    < 10 or > 20    (outside the range of {10 .. 20})
    e) @10:20   ≥ 10 and ≤ 20   (inside the range of {10 .. 20})"""

    threshold = str(threshold)
    return_data = float(return_data)
    l = []

    # a)
    if f_check_if_number(threshold):
        return f_thresholds_check_a(threshold, return_data)
    else:
        l = threshold.split(':')
        # b)
        if l[1] == "":
            return f_thresholds_check_b(l[0], return_data)
        # c)
        elif l[0] == "~":
            return f_thresholds_check_c(l[1], return_data)
        # d)
        elif f_check_if_number(l[0]) and f_check_if_number(l[1]):
            return f_thresholds_check_d(l[0], l[1], return_data)
        # e)
        elif l[0][0] == "@":
            l_new = []
            for v in l:
                v = v.replace("@", "")
                l_new.append(v)
            l = l_new
            return f_thresholds_check_e(l[0], l[1], return_data)

    return None


def f_thresholds_check_sub04(data):
    """ Helper function for f_thresholds_check_sub03
    Function check is return_data number if is warning or critical"""

    msg = (f"[ERROR] Return data '{data}' is not number. It is not possible "
           "to use '--warning' or '--critical'. For a numeric value, use "
           "'--check-one=' and select an item with a numeric value. "
           "For string value use parameters "
           "'--warning-str' or '--critical-str'.")

    if data is False:
        nagios_unknown(msg)
        # bcolors.fail(msg)
        # sys.exit(stdout_unknown)

    if data is True:
        nagios_unknown(msg)
        # bcolors.fail(msg)
        # sys.exit(stdout_unknown)

    try:
        data = float(data)
    except ValueError:
        nagios_unknown(msg)
        # bcolors.fail(msg)
        # sys.exit(stdout_unknown)


def f_thresholds_check_a(threshold, return_data):
    """ Helper function for f_thresholds_check_sub03
    a) 10    < 0 or > 10     (outside the range of {0 .. 10})"""
    threshold = float(threshold)
    if return_data < 0 or return_data > threshold:
        return True
    return False


def f_thresholds_check_b(threshold, return_data):
    """ Helper function for f_thresholds_check_sub03
    b) 10:      < 10            (outside {10 .. ∞})"""
    threshold = float(threshold)
    if return_data < threshold:
        return True
    return False


def f_thresholds_check_c(threshold, return_data):
    """ Helper function for f_thresholds_check_sub03
    c) ~:10     > 10            (outside the range of {-∞ .. 10})"""
    threshold = float(threshold)
    if return_data > threshold:
        return True
    return False


def f_thresholds_check_d(threshold_min, threshold_max, return_data):
    """ Helper function for f_thresholds_check_sub03
    d) 10:20    < 10 or > 20    (outside the range of {10 .. 20})"""
    threshold_min = float(threshold_min)
    threshold_max = float(threshold_max)
    if return_data < threshold_min or return_data > threshold_max:
        return True
    return False


def f_thresholds_check_e(threshold_min, threshold_max, return_data):
    """ Helper function for f_thresholds_check_sub03
    e) @10:20   ≥ 10 and ≤ 20   (inside the range of {10 .. 20})"""
    threshold_min = float(threshold_min)
    threshold_max = float(threshold_max)
    # if (return_data >= threshold_min) and (return_data <= threshold_max):
    if threshold_max >= return_data >= threshold_min:
        return True
    return False


# FUNCTION [12] - WARNING/CRITICAL STRING =====================================
# ::: function warning-str / critical-string :::::::::::::::::::::::::::::::
def f_thresholds_str_check(warning, critical, data_list):
    """ Functions for complete evaluation of WARNING/CRITICAL (is string)"""

    # helpder function
    # f_thresholds_str_check_sub02 - Add data to one list
    # f_thresholds_str_check_sub03 - Convert lower
    # f_thresholds_str_check_sub04 - Check is data or threshold multi value
    # f_thresholds_str_check_sub05 - Function comapre threshold and return_data
    # f_thresholds_str_check_sub06 - Add threshold to list
    # f_thresholds_str_check_sub07 - --one-found
    # f_thresholds_str_check_sub08 - Final evaluation list with --invert-state

    if warning and critical:
        if f_thresholds_str_check_sub01(critical, data_list):
            nagios_critical(msg_output)
        elif f_thresholds_str_check_sub01(warning, data_list):
            nagios_warning(msg_output)
        else:
            nagios_ok(msg_output)
    elif critical:
        if f_thresholds_str_check_sub01(critical, data_list):
            nagios_critical(msg_output)
        else:
            nagios_ok(msg_output)
    elif warning:
        if f_thresholds_str_check_sub01(warning, data_list):
            nagios_warning(msg_output)
        else:
            nagios_ok(msg_output)


def f_thresholds_str_check_sub01(threshold, data_list):
    """Helper function for f_thresholds_check
    Cutting when return_data_list list.Threshold and return_data_list convert
    lowercase. Eliminate case-sensitive"""

    global event_found

    # list for boolean
    l = []

    # check is multi value(threshold, service, return_data)
    f_thresholds_str_check_sub04(threshold, data_list)

    # convert to lower eliminate case-sensitive
    threshold = f_thresholds_str_check_sub03(threshold)
    data_list = f_thresholds_str_check_sub03(data_list)

    # add threshold to list
    threshold_l = f_thresholds_str_check_sub06(threshold)

    if args_multi:
        l = f_thresholds_str_check_sub05(threshold_l, data_list)
    elif args_one_found:
        l = f_thresholds_str_check_sub07(threshold_l, data_list)
    else:
        # without arguments
        l = f_thresholds_str_check_sub07(threshold_l, data_list)

    dbg("return_data to one list & low:\t", data_list)
    dbg("threshold_l lower:\t\t", threshold_l)
    dbg("Compare thresholds with return_data: ", str(l))

    # summary True in list. Use for eventlog
    event_found = f_thresholds_check_summary(l)

    # finale evalution
    return f_thresholds_str_check_sub08(l)


def f_thresholds_str_check_sub03(data):
    """Helper function for  f_thresholds_str_check
       Convert to lower return_data or threshold. All is STRING"""

    l = []

    if isinstance(data, list):
        # replace bolean object
        for v in data:
            # all is string so intiger and float
            v = str(v)
            if v is True:
                v = "true"
                l.append(v)
            elif v is False:
                v = "false"
                l.append(v)
            else:
                l.append(v.lower())
        return l
    else:
        value = str(data)
        return value.lower()


def f_thresholds_str_check_sub04(threshold, data_list):
    """Helper function for  f_thresholds_str_check_sub01
       Check is data or threshold multi value"""

    global args_multi

    # msg = (f"[ERROR] For monitoring multiple items use the '--multi' "
    #        f"parameter. Threshold is: [{threshold}]. Service is: "
    #        f"{services_list}, return data is: {data_list}.")

    threshold_quantity = len(f_thresholds_str_check_sub06(threshold))
    services_quantity = len(services_list)
    data_list_quantity = len(data_list)

    if args_one_found:
        return True

    if not args_multi:
        if threshold_quantity > 1 or services_quantity > 1 or \
                                     data_list_quantity > 1:
            args_multi = True
            # nagios_unknown(msg)

    return None


def f_thresholds_str_check_sub05(threshold: str, data):
    """Helper function for f_thresholds_str_check_sub04.
    Function comapre threshold and return_data True/False
    use Regular expression"""

    list_index = len(data)

    # check if same number arguments
    len_threshold = len(threshold)
    len_data = len(data)

    # the problem is, for example, when a user is added, the number of
    # arguments is different
    if len_threshold < len_data:
        difference = len_data - len_threshold
        threshold.extend(int(difference) * ["NOT-SAME-NUBER-AS-DATA"])
        # threshold.append("NOT-SAME-NUBER-AS-DATA")
        list_index = len(data)
    if len_threshold > len_data:
        difference = len_threshold - len_data
        data.append(int(difference) * "NOT-SAME-NUBER-AS-THRESHOLD")
        # data.append("NOT-SAME-NUBER-AS-THRESHOLD")
        list_index = len(data)

    if args_reqex_full:
        return f_thresholds_str_check_sub05_01(list_index, threshold, data)

    elif args_reqex_search:
        return f_thresholds_str_check_sub05_02(list_index, threshold, data)

    else:
        # string
        return f_thresholds_str_check_sub05_03(list_index, threshold, data)


def f_thresholds_str_check_sub05_01(list_index, threshold, data):
    """Helper function for f_thresholds_str_check_sub05.
    re.fullmatch"""

    l = []
    for i in range(list_index):
        if re.fullmatch(threshold[i], data[i]):
            l.append(True)
        else:
            l.append(False)
    return l


def f_thresholds_str_check_sub05_02(list_index, threshold, data):
    """Helper function for f_thresholds_str_check_sub05.
    re.search"""

    l = []
    # reqex search
    for i in range(list_index):
        if re.search(threshold[i], data[i]):
            l.append(True)
        else:
            l.append(False)
    return l


def f_thresholds_str_check_sub05_03(list_index, threshold, data):
    """Helper function for f_thresholds_str_check_sub05.
    string"""

    l = []
    for i in range(list_index):
        if threshold[i] == data[i]:
            l.append(True)
        else:
            l.append(False)
    return l


def f_thresholds_str_check_sub06(threshold):
    """Helper function for f_thresholds_str_check_sub01.
    Add threshold to list"""

    l = threshold.split(',')
    return l


def f_thresholds_str_check_sub07(threshold: str, data):
    """Helper function for f_thresholds_str_check_sub04.
    Function for normal evalution or with --one-found. Use reqex is set args"""

    msg = ("[ERROR] Only one threshold is allowed for the argument " +
           "'--one-found' " + str(threshold) + ".")

    if args_one_found:
        if len(threshold) > 1:
            # nagios_unknown(msg)
            bcolors.fail(msg)
            sys.exit(stdout_unknown)

    list_index = len(data)

    if args_reqex_full:
        return f_thresholds_str_check_sub07_01(list_index, threshold, data)

    elif args_reqex_search:
        return f_thresholds_str_check_sub07_02(list_index, threshold, data)

    else:
        # string
        return f_thresholds_str_check_sub07_03(list_index, threshold, data)


def f_thresholds_str_check_sub07_01(list_index, threshold, data):
    """Helper function for f_thresholds_str_check_sub07
       re.fullmatch"""

    l = []
    for i in range(list_index):
        if re.fullmatch(threshold[0], data[i]):
            l.append(True)
        else:
            l.append(False)
    return l


def f_thresholds_str_check_sub07_02(list_index, threshold, data):
    """Helper function for f_thresholds_str_check_sub07
       re.search"""

    l = []
    for i in range(list_index):
        if re.search(threshold[0], data[i]):
            l.append(True)
        else:
            l.append(False)
    return l


def f_thresholds_str_check_sub07_03(list_index, threshold, data):
    """Helper function for f_thresholds_str_check_sub07
       string"""

    l = []
    for i in range(list_index):
        if threshold[0] == data[i]:
            l.append(True)
        else:
            l.append(False)
    return l


def f_thresholds_str_check_sub08(l):
    """Helper function for  f_thresholds_str_check_sub01
       Final evaluation list with --invert-state"""

    if args_one_found:
        return f_thresholds_str_check_sub08_01(l)

    # normal and --multi check
    if all(item is True for item in l):
        if args_invert:
            bool_return = True
            return bool_return
        else:
            return False
    else:
        if all(item is False for item in l):
            if args_invert:
                return False
        return True


def f_thresholds_str_check_sub08_01(l):
    """Helper function for f_thresholds_str_check_sub08
       args_one_found"""

    if True in l:
        if args_invert:
            bool_return = True
            return bool_return
        else:
            return False
    else:
        if False in l:
            if args_invert:
                return False
        return True


# FUNCTION [13] - OTHER =======================================================
# ::: function test if string int or float or string:::::::::::::::::::::::::::
def f_check_if_number(v):
    """Function check is value number(int or float)"""
    # It is necessary to convert everything to a string, when it can be in
    # boolean=False/True. TThen the string is converted and tested
    v = str(v)
    try:
        v = int(v)
        return True
    except ValueError:
        try:
            v = float(v)
            return True
        except ValueError:
            v = str(v)
            return False


# ::: function check is warning critical Nagios corect format :::::::::::::::::
def f_treshold_corect(threshold):
    """ Function for check corect Nagios threshold format"""

    msg = ("[ERROR] Wrong Nagios threshold format '" + str(threshold) +
           "'." + "\n" +
           "Look at 'https://nagios-plugins.org/doc/guidelines.html#" +
           "THRESHOLDFORMAT'.")
    l = []

    # for perf data check nagios threshold format
    if threshold is False:
        return True

    # a)
    if f_check_if_number(threshold):
        return True
    else:
        if ":" not in str(threshold):
            bcolors.fail_w(msg)
            sys.exit(stdout_unknown)
        else:
            l = threshold.split(':')

            # b)
            if l[1] == "":
                f_treshold_corect_sub01(l[0], msg)
                return True
            # c)
            elif l[0] == "~":
                f_treshold_corect_sub01(l[1], msg)
                return True
            # e)
            elif l[0][0] == "@":
                l_new = []
                for v in l:
                    v = v.replace("@", "")
                    l_new.append(v)
                l = l_new
                f_treshold_corect_sub01(l[0], msg)
                f_treshold_corect_sub01(l[1], msg)
                return True
            # d)
            elif f_treshold_corect_sub01(l[0], msg) and f_treshold_corect_sub01(l[1], msg):
                return True
            else:
                bcolors.fail_w(msg)
                sys.exit(stdout_unknown)


# ::: function check check is number ::::::::::::::::::::::::::::::::::::::::::
def f_treshold_corect_sub01(threshold, message):
    """ Helper function for f_check_if_number
    Function check is number"""
    try:
        threshold = float(threshold)
        return True
    except ValueError:
        bcolors.fail_w(message)
        sys.exit(stdout_unknown)


# ::: functions for --print-wmi :::::::::::::::::::::::::::::::::::::::::::::::
def f_wmi_filer_arg(wmi_class):
    """Funtion for make wql to WMI query"""

    wql = ""

    if args_print_wmidata or not args_services:
        wql = "*"
    else:
        wql = str(args_services)

    if args_wql:
        return str(args_wql)
    else:
        return str("SELECT " + wql + " FROM " + wmi_class)


def f_print_wmi_data(data, namespace, wmi_filter):
    """Function for --print-services"""

    k_len = 0

    # width of the column
    if args_print_wmidata:
        for k, v in data.items():
            if len(k) > k_len:
                k_len = len(k)

        # header
        print(bcolors.W + "PRINT WMI DATA FOR:\n" + bcolors.ENDC +
              "Namespace:\t'" + str(namespace) + appo + "\n"
              "WQL Query:\t'" + str(wmi_filter) + appo + "\n")
        print(bcolors.W + "-" * 119 + "\n" + "Services" + " " * (k_len - 6) +
              "WMI Data", "-" * 119 + bcolors.ENDC, sep="\n")

        for k, v in data.items():
            widht = k_len - len(k)
            print(f'{k} {" " * widht} {v}')
        sys.exit(stdout_ok)
    else:
        return True


# ::: functions for eventlog ::::::::::::::::::::::::::::::::::::::::::::::::::
def f_eventlog_timeback():
    """Function convert UTM time for eventlog"""

    msg = ("[ERROR] Wrong format for '--timeback=' show '--help'.")
    l = []

    if "h" in args_timeback:
        l = args_timeback.split('h')
        timeback_m = int(l[0]) * 60
    elif "m" in args_timeback:
        l = args_timeback.split('m')
        timeback_m = int(l[0])
    elif f_check_if_number(args_timeback):
        l.append(args_timeback)
        timeback_m = int(l[0]) * 60
    else:
        bcolors.fail(msg)
        sys.exit(stdout_critical)

    utctime_now = datetime.utcnow()
    timeback = utctime_now - timedelta(minutes=timeback_m)

    # microsoft have microsecond in 8 digit python only 6
    return timeback.strftime('%Y%m%d%H%M%S.%f') + ("00")


# ::: functions for eventlog ::::::::::::::::::::::::::::::::::::::::::::::::::
def f_eventlog_file():
    """Function for eventlog choice eventlogfile"""

    o = ""

    if args_logfile:
        l = []
        o = ""
        l = args_logfile.split(",")

        len_l = len(l) - 1
        for v in l:
            o += ("Logfile=" + appo + v + appo)
            if len_l >= 1 < len(l):
                len_l = len_l - 1
                o += " OR "

    if args_logfile:
        if f_eventlog_event_not(args="logfile"):
            return f" NOT ({o})"
        else:
            return f" ({o})"
    else:
        return o


# ::: functions for eventlog ::::::::::::::::::::::::::::::::::::::::::::::::::
def f_eventlog_level():
    """Function for eventlog choce loglevel
    Type:
    1-Error, 2-Warning, 3-Information,
    4-Security Audit Success, 5-Security Audit Failure."""

    msg = ("[ERROR] Wrong format for '--loglevel=' show '--help'.")
    l = []
    o = ""

    if f_check_if_number(args_loglevel):
        l.append(args_loglevel)
    else:
        l = args_loglevel.split(",")

    len_l = len(l) - 1
    for v in l:
        if f_check_if_number(v):
            o += ("EventType=" + str(v))
            if len_l >= 1 < len(l):
                len_l = len_l - 1
                o += " OR "
        else:
            bcolors.fail(msg)
            sys.exit(stdout_critical)

    if f_eventlog_event_not(args="loglevel"):
        return f" AND NOT ({o})"
    else:
        return f" AND ({o})"


# ::: functions for eventlog ::::::::::::::::::::::::::::::::::::::::::::::::::
def f_eventlog_id():
    """Function for eventlog choice eventID"""

    msg = ("[ERROR] Wrong format for '--eventid=' show '--help'.")

    if args_eventid:
        l = []
        o = ""
        l = args_eventid.split(",")

        len_l = len(l) - 1
        for v in l:
            if f_check_if_number(v):
                o += ("EventCode=" + v)
                if len_l >= 1 < len(l):
                    len_l = len_l - 1
                    o += " OR "
            else:
                bcolors.fail(msg)
                sys.exit(stdout_critical)

    if args_eventid:
        if f_eventlog_event_not(args="eventid"):
            return f" AND NOT ({o})"
        else:
            return f" AND ({o})"
    else:
        return ""


# ::: functions for eventlog ::::::::::::::::::::::::::::::::::::::::::::::::::
def f_eventlog_eventsource():
    """Function for eventlog choice eventsource"""

    o = ""

    if args_eventsource:
        l = []
        o = ""
        l = args_eventsource.split(",")

        len_l = len(l) - 1
        for v in l:
            o += ("SourceName=" + appo + v + appo)
            if len_l >= 1 < len(l):
                len_l = len_l - 1
                o += " OR "

    if args_eventsource:
        if f_eventlog_event_not(args="eventsource"):
            return f" AND NOT ({o})"
        else:
            return f" AND ({o})"
    else:
        return o


# ::: functions for eventlog ::::::::::::::::::::::::::::::::::::::::::::::::::
def f_eventlog_eventcategory():
    """Function for eventlog choice eventcategory"""

    o = ""

    if args_eventcategory:
        l = []
        o = ""
        l = args_eventcategory.split(",")

        len_l = len(l) - 1
        for v in l:
            o += ("CategoryString=" + appo + v + appo)
            if len_l >= 1 < len(l):
                len_l = len_l - 1
                o += " OR "

    if args_eventcategory:
        if f_eventlog_event_not(args="eventcategory"):
            return f" AND NOT ({o})"
        else:
            return f" AND ({o})"
    else:
        return o


# ::: functions for eventlog ::::::::::::::::::::::::::::::::::::::::::::::::::
def f_eventlog_eventmsg():
    """Function for eventlog choice eventmsg"""

    o = ""

    if args_eventmsg:
        l = []
        o = ""
        l = args_eventmsg.split(",")

        len_l = len(l) - 1
        for v in l:
            o += ("Message LIKE " + appo + v + appo)
            if len_l >= 1 < len(l):
                len_l = len_l - 1
                o += " OR "

    if args_eventmsg:
        if f_eventlog_event_not(args="eventmsg"):
            return f" AND NOT ({o})"
        else:
            return f" AND ({o})"
    else:
        return o


# ::: functions for eventlog ::::::::::::::::::::::::::::::::::::::::::::::::::
def f_eventlog_event_not(args):
    """Function for eventlog choice --event-not"""

    if args_event_not:
        l = []
        l = args_event_not.split(",")

    if args_event_not:
        if args in l:
            return True

    return False


# ::: function return summary of threshold ::::::::::::::::::::::::::::::::::::
def f_thresholds_check_summary(data_list):
    """Helper function for f_thresholds_check_sub01 and
       Return summary of found True in list"""

    n = 0

    for v in data_list:
        if v is True:
            n = n + 1
    return int(n)


# ::: function add day to date/time :::::::::::::::::::::::::::::::::::::::::::
def f_convert_data_time(data):
    """Function add day to date/time"""

    date_now = datetime.now()
    d = {}

    if args_datetime:
        for k, v in data.items():
            if isinstance(v, str):
                try:
                    v_date = v[:19]
                    # print(v_date)
                    date_object = datetime.strptime(v_date, "%Y-%m-%d %H:%M:%S")
                    # print(type(date_object))
                    # print(date_object)
                    if isinstance(date_object, datetime):
                        timeback = date_now - date_object
                        d = f_convert_data_time_01(args_datetime, timeback, k)
                except (ValueError, TypeError):
                    d[k] = (v)
            else:
                d[k] = (v)
    else:
        d = data

    return d


def f_convert_data_time_01(args_datetime01, timeback, k):
    """Help function for f_convert_data_time"""

    d = {}

    if args_datetime01 == "d":
        d[k] = int(timeback.days)
    elif args_datetime01 == "h":
        hours = int(timeback.total_seconds()) / 3600
        d[k] = int(hours)
    elif args_datetime01 == "m":
        minutes = int(timeback.total_seconds()) / 60
        d[k] = int(minutes)
    elif args_datetime01 == "s":
        seconds = int(timeback.total_seconds())
        d[k] = int(seconds)
    else:
        d[k] = int(timeback.days)

    return d


# ::: function human_readable :::::::::::::::::::::::::::::::::::::::::::::::::
def f_human_readable(data):
    """Function convert MB"""

    # date_now = datetime.now()
    d = {}

    if args_human_readable:
        for k, v in data.items():
            # print(v)
            if isinstance(v, list):
                v = f_human_readable_02(k, v)

            if f_check_if_number(v):
                d[k] = f_human_readable_01(v)
            else:
                d[k] = v
    else:
        d = data

    return d


def f_human_readable_01(data):
    """Help function for f_human_readable"""

    if args_human_readable == "KB":
        return data / 1024
    elif args_human_readable == "MB":
        return data / 1024 / 1024
    elif args_human_readable == "GB":
        return data / 1024 / 1024 / 1024
    elif args_human_readable == "TB":
        return data / 1024 / 1024 / 1024 / 1024

    return None


def f_human_readable_02(key, value):
    """Help function for f_human_readable"""

    l = []

    for v in value:
        if f_check_if_number(v):
            v = f_human_readable_01(v)
            l.append(v)
            # break
        else:
            l.append(v)

    return l


# ::: function format output --msg-desc-ext :::::::::::::::::::::::::::::::::::
def f_msg_desc_ext(text):
    """ Function format output --msg-desc-ext"""

    msg = ""
    l = []

    if args_msg_desc_ext:
        l = text.split(',')
        len_l = len(l)
        index = len_l
        for v in l:
            msg += v
            index = index - 1
            if index == 0:
                msg += ""
            else:
                msg += "\n"

    return msg


def f_null_data(data):
    """ Function for null data example WQL query"""

    d = {}

    if args_null:
        srv_list = f_add_args_list(args_services, name_of_list="",
                                   text="", tab="")
        if not data:
            for k in srv_list:
                d[k] = "Not-Found"
            return d

    return data


# ::: function count for warning critical :::::::::::::::::::::::::::::::::::::
def f_thresholds_count(data_list):
    """Function return count in data list"""
    global event_found

    l = []
    l.append(len(data_list))
    # print(l)

    # summary True in list. Use for eventlog
    event_found = len(data_list)

    dbg('Count\t\t\t\t', l)

    return l


# FUNCTION [14] - QUERY + DEBUG ===============================================
# ::: function for services query :::::::::::::::::::::::::::::::::::::::::::::
def f_query_services():
    """ Function for services query """
    global return_data_list, return_data_dict, data_dict, perfdata_dict
    global perfdata, msg_output

    return_data_list = f_returned_list(wmi_data)
    return_data_dict = f_returned_dict(wmi_data)
    data_dict = f_data_dict(wmi_data)
    perfdata_dict = f_perfdata_to_dict(data_dict)
    perfdata = f_perfdata(args_warning, args_critical, perfdata_dict)
    msg_output = f_services(wmi_data)


# ::: function for debug query ::::::::::::::::::::::::::::::::::::::::::::::::
def f_query_debug():
    """ Function for debug query """
    dbg_separator("RETURN DATA")
    dbg("HTTP/WWI request - data type\t", type(wmi_data))
    dbg('\'return_data_list\'\t\t', return_data_list)
    dbg('\'return_data_dict\'\t\t', return_data_dict)
    dbg('\'data_dict\'\t\t\t', data_dict)
    dbg_separator("PERFORMANCE DATA")
    dbg('\'perfdata_dict\'\t\t\t', perfdata_dict)
    dbg_alignment('\'perfdata\'\t\t\t', perfdata)
    dbg_separator("MESSAGE OUTPUT")
    dbg('\'msg_output\'\t\t\t', msg_output)
    dbg_separator("THRESHOLD")


# FUNCTION [15] - MAIN QUERY  =================================================
# ::: function for main query launch ::::::::::::::::::::::::::::::::::::::::::
def f_main_query_launch(namespace, wmi_class, query, url):
    """ MAIN function for completed run query"""

    global wmi_data, extend_data

    if args_list_services:
        f_list_services(query, url, wmi_class, namespace)

    wmi_filter = f_wmi_filer_arg(wmi_class)

    # debug
    dbg('\'WMI Query\'\t\t\t', wmi_filter)
    dbg('\'WMI Namespace\'\t\t\t', namespace)
    wmi_data = f_http_get_wmi(namespace, wmi_filter)
    wmi_data = f_convert_data_time(wmi_data)
    wmi_data = f_human_readable(wmi_data)
    wmi_data = f_null_data(wmi_data)

    f_print_wmi_data(wmi_data, namespace, wmi_filter)

    f_args_parameters_add_to_list()
    f_args_add_to_dictionary()

    extend_data = f_msg_ouput_extend(wmi_data)

    if args_services:
        f_query_services()
        f_query_debug()

    if args_warning or args_critical:
        f_thresholds_check(args_warning, args_critical, return_data_list)

    if args_warning_str or args_critical_str:
        f_thresholds_str_check(args_warning_str, args_critical_str,
                               return_data_list)

    # if not warning or critical set
    nagios_ok(msg_output)


# DEBUG VARIABLE & FUNCTION ===================================================
# # debug all variable
all_var = []
for var in [name for name in dir() if name[:2] != '__' and name[:2] != 'f_' and name[:5] != 'args_']:
    all_var.append(var)
dbg('All variable (no args_ & f_)\t\t\t', all_var)

# debug all function
all_function = []
for var in [name for name in dir() if name[:2] == 'f_']:
    all_function.append(var)
dbg('All function\t\t\t', all_function)

dbg_separator("WMI QUERY/DATA")


# FUNCTION [16] - MAIN QUERY LAUNCH ===========================================
# MAIN CHECK [--query=os] Windows OS information ::::::::::::::::::::::::::::::
def f_main__query_os():
    """Main check query"""

    global args_services, args_name, args_no_perfdata

    if args_query == 'os':
        namespace = "root/cimv2"
        wmi_class = "Win32_OperatingSystem"
        url = ("https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/"
               "win32-operatingsystem")

        if not args_services:
            args_services = ("Status,Caption,OSArchitecture,InstallDate,"
                             "CSName,ProductType,Version,CurrentTimeZone,"
                             "LastBootUpTime,BuildNumber,CodeSet,Locale,"
                             "OSLanguage,SystemDrive,WindowsDirectory")
            if not args_name:
                args_name = ("Status,OS,Arch,InstallDate,Hostname,ProductType,"
                             "Version,TimeZone,LastBoot,BuildNumber,CodeSet,"
                             "Locale,OSLanguage,SystemDrive,WinDir")
            if not args_no_perfdata:
                args_no_perfdata = True

        f_main_query_launch(namespace, wmi_class, args_query, url)


# MAIN CHECK [--query=firewall] Windows OS firewall check :::::::::::::::::
def f_main__query_firewall():
    """Main check query"""

    global args_services, args_name, args_critical_str, args_multi

    if args_query == 'firewall':
        namespace = "root/StandardCimv2"
        wmi_class = "MSFT_NetFirewallProfile"
        url = ("https://learn.microsoft.com/en-us/previous-versions/windows/"
               "desktop/wfascimprov/msft-netfirewallprofile")

        if not args_services:
            args_services = "Name,Enabled"
            if not args_name:
                args_name = "Zones,Enabled"
            if not args_critical_str:
                args_critical_str = "domain,private,public,1,1,1"
            if not args_multi:
                args_multi = True

        f_main_query_launch(namespace, wmi_class, args_query, url)


# MAIN CHECK [--query=eventlog] eventLog ::::::::::::::::::::::::::::::::::
def f_main__query_eventlog():
    """Main check query"""

    global args_services, args_no_perfdata

    if args_query == 'eventlog':
        namespace = "root/cimv2"
        wmi_class = (f"Win32_NTLogEvent WHERE"
                     f"{f_eventlog_file()}"
                     f"{f_eventlog_level()}"
                     f" AND TimeGenerated > '{f_eventlog_timeback()}'"
                     f"{f_eventlog_id()}"
                     f"{f_eventlog_eventsource()}"
                     f"{f_eventlog_eventcategory()}"
                     f"{f_eventlog_eventmsg()}")

        url = ("https://learn.microsoft.com/en-us/previous-versions/windows/"
               "desktop/eventlogprov/win32-ntlogevent")
        args_no_perfdata = True

        if not args_services:
            args_services = "EventCode,Logfile,TimeWritten,Type,SourceName,CategoryString,Message"

        f_main_query_launch(namespace, wmi_class, args_query, url)


# MAIN CHECK [--query=network] tcp/ip information :::::::::::::::::::::::::
def f_main__query_network():
    """Main check query"""

    global args_services, args_name

    if args_query == 'network':
        namespace = "root/cimv2"
        wmi_class = "win32_networkadapterconfiguration WHERE IPEnabled=True"
        url = ("https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/"
               "win32-networkadapterconfiguration?source=recommendations")

        if not args_services:
            args_services = ("IPAddress,IPSubnet,DefaultIPGateway,"
                             "DNSServerSearchOrder,DNSDomainSuffixSearchOrder"
                             ",MACAddress,ServiceName")
            if not args_name:
                args_name = ("IPAddress,Mask,Gateway,DNS-Servers,DNS-suffix"
                             ",MACAddress,NiC")

        f_main_query_launch(namespace, wmi_class, args_query, url)


# MAIN CHECK [--query=dnscache] tcp/ip information :::::::::::::::::::::::::
def f_main__query_dnscache():
    """Main check query"""

    global args_services, args_no_perfdata

    if args_query == 'dnscache':
        namespace = "root/StandardCimv2"
        wmi_class = "MSFT_DNSClientCache"
        url = ("https://learn.microsoft.com/en-us/previous-versions/windows/"
               "desktop/dnsclientcimprov/msft-dnsclientcache")

        if not args_services:
            args_services = "Name,Data,TimeToLive"
        if not args_no_perfdata:
            args_no_perfdata = True

        f_main_query_launch(namespace, wmi_class, args_query, url)


# MAIN CHECK [--query=users] users information ::::::::::::::::::::::::::::
def f_main__query_users():
    """Main check query"""

    global args_services

    if args_query == 'users':
        namespace = "root/cimv2"
        wmi_class = "Win32_UserAccount WHERE Disabled=False"
        url = ("https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/"
               "win32-useraccount")

        if not args_services:
            args_services = ("Name,Lockout,Status")

        f_main_query_launch(namespace, wmi_class, args_query, url)


# MAIN CHECK [--query=lockusers] users information ::::::::::::::::::::::::
def f_main__query_lockusers():
    """Main check query"""

    global args_services, args_name, args_check_one, args_one_found
    global args_invert, args_critical_str

    if args_query == 'lockusers':
        namespace = "root/cimv2"
        wmi_class = "Win32_UserAccount WHERE Disabled=False"
        url = ("https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/"
               "win32-useraccount")

        if not args_services:
            args_services = "Lockout,Name"
            if not args_name:
                args_name = "Lockout local users,Local users"
            if not args_check_one:
                args_check_one = "Lockout"
            if not args_one_found:
                args_one_found = True
            if not args_invert:
                args_invert = True
            if not args_critical_str:
                args_critical_str = "True"

        f_main_query_launch(namespace, wmi_class, args_query, url)


# MAIN CHECK [--query=uptime] uptime info :::::::::::::::::::::::::::::::::
def f_main__query_uptime():
    """Main check query"""

    global args_services, args_name, args_datetime

    if args_query == 'uptime':
        namespace = "root/cimv2"
        wmi_class = "Win32_OperatingSystem"
        url = ("https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/"
               "win32-operatingsystem")

        if not args_services:
            args_services = "LastBootUpTime"
            if not args_name:
                args_name = "OS Uptime (Days) is"
            if not args_datetime:
                args_datetime = "d"

        f_main_query_launch(namespace, wmi_class, args_query, url)


# MAIN CHECK [--query=domain] domain/workgroup info :::::::::::::::::::::::
def f_main__query_domain():
    """Main check query"""

    global args_services, args_name, args_no_perfdata

    if args_query == 'domain':
        namespace = "root/cimv2"
        wmi_class = "Win32_ComputerSystem"
        url = ("https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/"
               "win32-computersystem")

        if not args_services:
            args_services = "Domain,DomainRole,Workgroup"
            if not args_name:
                args_name = "Domain,ServerRole,Workgroup"
            if not args_no_perfdata:
                args_no_perfdata = True

        f_main_query_launch(namespace, wmi_class, args_query, url)


# MAIN CHECK [--query=timezone] tomezone info :::::::::::::::::::::::::::::::::
def f_main__query_timezone():
    """Main check query"""

    global args_services, args_name, args_no_perfdata

    if args_query == 'timezone':
        namespace = "root/cimv2"
        wmi_class = "Win32_TimeZone"
        url = ("https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/"
               "win32-timezone")

        if not args_services:
            args_services = "Caption"
            if not args_no_perfdata:
                args_no_perfdata = True
            if not args_name:
                args_name = "Time zone"

        f_main_query_launch(namespace, wmi_class, args_query, url)


# MAIN CHECK [--query=serial] tomezone info :::::::::::::::::::::::::::::::::
def f_main__query_serial():
    """Main check query"""

    global args_services, args_name, args_no_perfdata

    if args_query == 'serial':
        namespace = "root/cimv2"
        wmi_class = "Win32_BIOS"
        url = ("https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/"
               "win32-bios")

        if not args_services:
            args_services = ("SerialNumber,ReleaseDate,"
                             "Name,Manufacturer,BIOSVersion")
            if not args_no_perfdata:
                args_no_perfdata = True
            if not args_name:
                args_name = ("Serial Number,BIOS Date,BIOS Name,Manufacturer,"
                             "BIOS Version")

        f_main_query_launch(namespace, wmi_class, args_query, url)


# MAIN CHECK [--query=hwinfo] hwinfo info :::::::::::::::::::::::::::::::::::::
def f_main__query_hwinfo():
    """Main check query"""

    global args_services, args_name, args_no_perfdata

    if args_query == 'hwinfo':
        namespace = "root/cimv2"
        wmi_class = "Win32_ComputerSystem"
        url = ("https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/"
               "win32-computersystem")

        if not args_services:
            args_services = ("Model,Manufacturer,NumberOfProcessors,"
                             "NumberOfLogicalProcessors,TotalPhysicalMemory,"
                             "SystemSKUNumber,HypervisorPresent")
            if not args_no_perfdata:
                args_no_perfdata = True
            if not args_name:
                args_name = ("Model, Manufacturer,Processors,Processors"
                             "(Logical),PhysicalMemory,Manufacturer code,Virtual")

        f_main_query_launch(namespace, wmi_class, args_query, url)


# MAIN CHECK [--query=wql] OWN WQL guery ::::::::::::::::::::::::::::::::::
def f_main__query_wql():
    """Main check query"""

    global msg_output

    if args_query == 'wql':

        namespace = args_namespace
        wmi_class = args_wql
        url = ("https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/"
               "win32-provider")

        if not args_services:
            wmi_class = "Win32_OperatingSystem"
            msg_output = (" NOTICE: For a complete list of services, use "
                          "the '--print-wmidata' and then you must define "
                          "'--wql=' and '--services=' ")
        f_main_query_launch(namespace, wmi_class, args_query, url)


###############################################################################
# MAIN CHECK ##################################################################
###############################################################################

def main():
    """MAIN FUNCTION"""

    f_main__query_os()

    f_main__query_firewall()

    f_main__query_eventlog()

    f_main__query_network()

    f_main__query_dnscache()

    f_main__query_users()

    f_main__query_lockusers()

    f_main__query_uptime()

    f_main__query_domain()

    f_main__query_timezone()

    f_main__query_serial()

    f_main__query_hwinfo()

    f_main__query_wql()


if __name__ == '__main__':
    main()
