# -*- coding: utf-8 -*-
import argparse
import re
import os

# Create an argparser instance
parser = argparse.ArgumentParser(description='XSS Finder - Vulnerable Tags are always hidden until you look for them')

# We add and argument "p" 
parser.add_argument('-p', '--path', dest='pages_path', required=True, 
                    help='The path of the folder containing the pages search')

# Parse the passed arguments
args = parser.parse_args()

# Path to the application Web Pages
pages_path = args.pages_path

if pages_path == "":
    print("[*] There is no path to search [*]")
    exit()

list_of_all_pages = []

# This will grab every page in the folder (recursively) and create a list
for root, dirs, files in os.walk(pages_path):
    for page_names in files:
        # Removes the '\' and replace them with '/' (Normalize Path Format) 
        full_path_of_page = os.path.join(root, page_names).replace('\\','/')
        
        # Checks weather the page is a .xhtml / .jsp
        if (".xhtml" in full_path_of_page) or (".jsp" in full_path_of_page):
            list_of_all_pages.append(full_path_of_page)

# Regular expressions used to search the pages
regex_list = []

# JSF / PrimeFaces

# If the dialog contains a "selectItems" tag, an XSS might happen in when it pop's up
regex_list.append(re.compile(r'<p:dialog.*</p:dialog>', re.MULTILINE | re.DOTALL | re.IGNORECASE))

# If mojarra is < 2.2.6 this is maybe vulnerable to XSS
regex_list.append(re.compile(r"<f:selectItems.*itemLabel.*\/>"))

# If we have controle over the data this is vulnerable to XSS
regex_list.append(re.compile(r"<h:outputLink.*\/>"))

# If "escape" is present and it's equal to "False" this is vulnerable to XSS
regex_list.append(re.compile(r"<h:outputText.*escape.*\/>"))
regex_list.append(re.compile(r"<p:outputLabel.*escape.*\/>"))
regex_list.append(re.compile(r".*escape=.*\/>"))

if len(regex_list) == 0:
    print("[*] You're Regex List is empty [*]")

with open("TagList.txt", "w") as TagListFile:
    # Loop on every file on the list of pages
    for each_page in list_of_all_pages:
        # Open the file for read
        with open(each_page, "r") as page:
            # Grab the content of the file as it is
            page_content = page.read()

            # Start looping through our regular expressions list
            for regex in regex_list:
                str_regex = regex.__repr__()
                try:
                    # Grab the result of the regex search, then we have two cases
                    list_of_tags = regex.findall(page_content)

                    if list_of_tags != [] :
                        # First case : it's a "<p:dialog> </p:dialog>" tag
                        if "p:dialog" in str_regex:

                            # We search if contains an "<f:selectItems />" tag
                            itemLabel_Regex = re.compile(r"<f:selectItems.*itemLabel.*\/>")
                            for each_dialog_tag in list_of_tags:
                                tmp_res = itemLabel_Regex.findall(each_dialog_tag)

                                # Then for each element we check if it contains dynamic data (That can be controlled by the user)
                                for each_selectItems_tag in tmp_res:
                                    if "bundle" in each_selectItems_tag and "#{" not in each_selectItems_tag:
                                        # If it doesn't, we remove the element
                                        tmp_res.remove(each_selectItems_tag)
                                
                                # If the list is empty, that means that the dialog tag doesn't contain any data that we can modify 
                                if tmp_res == []:
                                    list_of_tags.remove(each_dialog_tag)
                            
                            # Else we write the result with the file name it came from 
                            if list_of_tags != []:
                                TagListFile.write("REGEX USED : " + str_regex + "\n")
                                TagListFile.write("You can find this in : " + each_page + "\n\n")
                                for each_dialog_tag in list_of_tags:
                                    for each_line in each_dialog_tag:
                                        TagListFile.write(each_line)
                                TagListFile.write("\n\n")
                        
                        # Second Case : Everything else
                        else:
                            filtered_list = []
                            for elements in list_of_tags:
                                # "Bundle" indicates data coming from the server (Not user controlled) 
                                # so we remove strings that contains it, and "#{" indicates dynamic data 
                                # (Maybe it's user controlled) so we keep it 
                                if "bundle" not in elements and "#{" in elements:
                                    filtered_list.append(elements.strip("\n"))

                            TagListFile.write("REGEX : " + str_regex + " \n\n")
                            TagListFile.write("You can find this in : " + each_page + "\n\n")
                            if filtered_list != []:
                                for elements in filtered_list:
                                    TagListFile.write(elements + "\n")
                                    
                except (NameError, ValueError, TypeError, FileExistsError, FileNotFoundError) as e:
                    print("[*] An ERROR Occurred [*]")
                    print(e)
