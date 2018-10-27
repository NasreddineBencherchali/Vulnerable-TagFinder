# -*- coding: utf-8 -*-
import subprocess
import argparse

parser = argparse.ArgumentParser(description='XSS Finder - Vulnerable Tags are always hidden until you look for them')

parser.add_argument('-p', '--path', dest='pages_path', required=True, 
                    help='The path of the folder containing the pages search')

# Parse the passed arguments
args = parser.parse_args()

# Path to the application Web Pages
pages_path = args.pages_path

if pages_path == "":
    print("[*] There is no path to search [*]")
    exit()

# Regular expressions used to search the pages
regex_list = []

# JSF / PrimeFaces
regex_list.append(r"<f:selectItems.*itemLabel.*\/>") # If mojarra is < 2.2.6 this is vulnerable to XSS
regex_list.append(r"<h:outputLink.*\/>") # If we have controle over the data this is vulnerable to XSS
regex_list.append(r"<h:outputText.*escape.*\/>") # If "escape" is "False" this is vulnerable to XSS
regex_list.append(r"<p:outputLabel.*escape.*\/>") # If "escape" is "False" this is vulnerable to XSS
regex_list.append(r".*escape=.*\/>") # A general purpose Regex to find any tag that explicitly sets "escape" to "False"

if len(regex_list) == 0:
    print("[*] You're Regex List is empty [*]")

try:
    subprocess.check_output(["grep", "--help"])
except:
    print("[*] \"grep\" needs to be installed [*]")
    exit()

with open("TagList.txt", "w") as new_file:
    for regex in regex_list:
        try:
            list_of_tags = subprocess.check_output(["grep", "-Hrn", regex, pages_path]).decode("utf-8").split("\n")
            filtered_list = []
            for elements in list_of_tags:
                # "Bundle" indicates data coming from the server (Not user controlled) 
                # so we remove strings that contains it, and "#{" indicates dynamic data 
                # (Maybe it's user controlled) so we keep it 
                if "bundle" not in elements and "#{" in elements:
                    filtered_list.append(elements.strip("\n"))

            new_file.write("REGEX : " + regex + " \n\n")
            if filtered_list != []:
                for elements in filtered_list:
                    new_file.write(elements[len(pages_path) - 1 :] + "\n")
        except:
            print("[*]  No Element / Tag found using : \"" + regex + "\"  [*]")
