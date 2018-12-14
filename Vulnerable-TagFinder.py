# -*- coding: utf-8 -*-
import argparse
import re
import os
from packaging import version

# This function will delete elements based on a list of indices
def delete_from_list(indices_list):
    # We get both the global regex_list and the regex_list_repr
    global regex_list
    global regex_list_repr
    
    # We loop on the indices list with an enumerator because we need to reduce the index by the number of the index in the list each time we remove an element.
    # For example : lst = [1,2,3,4] ; indices = [0,2]
    # After we remove the first element indicated by the "indices" list from the list "lst"
    # Every element has shifted by one so we need to account for that in our loop
    for index, to_delete_index in enumerate(indices_list):
        to_delete_index -= index

        del regex_list_repr[to_delete_index]
        del regex_list[to_delete_index]

print("""
              _                      _     _              
 /\   /\_   _| |_ __   ___ _ __ __ _| |__ | | ___         
 \ \ / / | | | | '_ \ / _ \ '__/ _` | '_ \| |/ _ \        
  \ V /| |_| | | | | |  __/ | | (_| | |_) | |  __/        
   \_/  \__,_|_|_| |_|\___|_|  \__,_|_.__/|_|\___|        
                                                          
 _____                        ___ _           _           
/__   \__ _  __ _            / __(_)_ __   __| | ___ _ __ 
  / /\/ _` |/ _` |  _____   / _\ | | '_ \ / _` |/ _ \ '__|
 / / | (_| | (_| | |_____| / /   | | | | | (_| |  __/ |   
 \/   \__,_|\__, |         \/    |_|_| |_|\__,_|\___|_|   
            |___/                                         
""")

# Create an argparser instance
parser = argparse.ArgumentParser(description='Vulnerable Tag Finder - Vulnerable Tags are always hidden until you look for them.')

# We add arguments
parser.add_argument('-p', '--path', dest='pages_path', required=True, 
                    help='The path of the folder containing the pages search.')

parser.add_argument('-t', '--tech', dest='techs_names', required=False, nargs='*', 
                    help='The technologies used in the project (Support JSF, PrimeFaces) seperated by a semicolon.')

parser.add_argument('-l', '--libVer', dest='libs_versions', required=False, nargs='*', 
                    help='The versions of the libraries used in the project seperated by a semicolon.')

# Parse the passed arguments
args = parser.parse_args()

# Check if both arguments "-t" and -"l" are passed
if (vars(args)['techs_names'] is not None) and (vars(args)['libs_versions'] is not None) :
    # Check if both "techs_names" and "libs_versions" are not empty
    if len(vars(args)['techs_names']) == 0 or len(vars(args)['libs_versions']) == 0:
        print("[*] One or both of the arguments are empty  [*]")
        exit()
    else:
        # If both "-t" and "-l" arguments are present, they must have the same length
        if len(vars(args)['techs_names'][0].split(',')) != len(vars(args)['libs_versions'][0].split(',')) :
            print("[*] Both '-t' and '-l' arguments must have same length  [*]")
            exit()

# Check if "-t" argument is passed the "-l" must be present as well, and vice versa
elif ((vars(args)['techs_names'] is None) and (vars(args)['libs_versions'] is not None)) or ((vars(args)['techs_names'] is not None) and (vars(args)['libs_versions'] is None)) :
    print("[*] Both '-t' and '-l' arguments must be present  [*]")
    exit()


# Path to the application Web Pages
pages_path = args.pages_path

# We check if the arguments were not sent then we set them as empty lists
if args.techs_names is not None:
    techs_names = [tech_names.strip() for tech_names in args.techs_names[0].strip().split(',')]
else:
    techs_names = []

if args.libs_versions is not None:
    libs_versions = [libs_ver.strip() for libs_ver in args.libs_versions[0].strip().split(',')]
else:
    libs_versions = []

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

################################ 
########### JSF TAGS  ##########
################################

# If mojarra is < 2.2.6 this is vulnerable to XSS (Uncomment this if you're sure of the version of mojarra - Could lead to a lot of false positive)
# regex_list.append(re.compile(r"<f:selectItems.*itemLabel.*>"))

################################ 
######## PrimeFaces TAGS #######
################################
 
# The "title" attribute doesn't escape XSS in PrimeFaces prior to 6.3 
regex_list.append(re.compile(r'<p:tab.*title.*>'))
regex_list.append(re.compile(r"<p:commandButton.*title.*>"))

# The "headerText" attribute doesn't escape XSS in PrimeFaces prior to 6.3
regex_list.append(re.compile(r'<p:carousel.*headerText.*>'))

# The "footerText" attribute doesn't escape XSS in PrimeFaces prior to 6.3
regex_list.append(re.compile(r'<p:carousel.*footerText.*>'))

# The "emptyMessage" attribute doesn't escape XSS in PrimeFaces prior to 6.3
regex_list.append(re.compile(r"<p:dataGrid.*emptyMessage.*>"))
regex_list.append(re.compile(r"<p:dataList.*emptyMessage.*>"))
regex_list.append(re.compile(r"<p:treeTable.*emptyMessage.*>")) 

# The "addLabel" attribute doesn't escape XSS in PrimeFaces prior to 6.3
regex_list.append(re.compile(r"<p:pickList.*addLabel.*>"))

# The "labelTemplate" attribute doesn't escape XSS in PrimeFaces prior to 6.3
regex_list.append(re.compile(r"<p:progressBar.*labelTemplate.*>"))

# The "backLabel" attribute doesn't escape XSS in PrimeFaces prior to 6.3
regex_list.append(re.compile(r"<p:slideMenu.*backLabel.*>"))

# This is vulnerable to XSS, if it contains a "<p:column" tag, and PrimeFaces is > 6.3
regex_list.append(re.compile(r'<p:selectOneMenu[^>]*>(.+?)</p:selectOneMenu\s*>', re.IGNORECASE|re.MULTILINE|re.DOTALL))
regex_list.append(re.compile(r'<p:treeTable[^>]*>(.+?)</p:treeTable\s*>', re.IGNORECASE|re.MULTILINE|re.DOTALL))

# This is vulnerable to XSS, if it contains a "<f:selectItems" tag, and PrimeFaces is > 6.0.2
regex_list.append(re.compile(r'<p:selectManyMenu[^>]*>(.+?)</p:selectManyMenu\s*>', re.IGNORECASE|re.MULTILINE|re.DOTALL))

# Vulnerable to XSS in PrimeFaces < 6.0.2
regex_list.append(re.compile(r"<p:fieldset.*legend.*>"))

# Vulnerable to XSS in "filename" : PrimeFaces < 6.0.30
regex_list.append(re.compile(r"<p:fileUpload[\w\W]+?>"))

# Vulnerable to XSS in PrimeFaces < 6.0.30 ; 6.1.16 ; 6.2.1
regex_list.append(re.compile(r"<p:inputTextarea.*completeMethod.*>"))
regex_list.append(re.compile(r"<p:inputTextarea.*counterTemplate.*>"))

# Vulnerable to XSS in PrimeFaces < 6.0.30 ; 6.1.16
regex_list.append(re.compile(r"<p:button.*href.*>"))
regex_list.append(re.compile(r"<p:button.*target.*>"))

# "legend" is vulnerable to XSS in PF < 6.0.7
regex_list.append(re.compile(r"<p:chart.*>"))

# If we have controle over the data in the "href" attribute, this is vulnerable to XSS
regex_list.append(re.compile(r"<h:outputLink[\w\W]+?>"))

# Search for "<p:editor" and "<p:textEditor" as they maybe vulnerable to XSS
regex_list.append(re.compile(r'<p:textEditor[^>]*>(.+?)</p:textEditor\s*>', re.IGNORECASE|re.MULTILINE|re.DOTALL))
regex_list.append(re.compile(r"<p:editor[\w\W]+?>"))

# If "escape" is present and it's equal to "False" this is vulnerable to XSS
regex_list.append(re.compile(r"<.*escape=[\w\W]+?>"))

# Search for "DataExporter" component, to find if there is a CSV injection possibility
regex_list.append(re.compile(r"<p:dataExporter[\w\W]+?>"))

# Search for "transient" attribute, if it's equal to "true" then maybe this is vulnerable to CSRF
regex_list.append(re.compile(r"<.*transient=.*>"))

# Search if the application is printing any StackTraces
regex_list.append(re.compile(r"#{.*StackTrace.*}", re.IGNORECASE))

# Search for HTML, XHTML, JSP comments
regex_list.append(re.compile(r"<!--[\w\W]+?-->")) # HTML/XHTML
regex_list.append(re.compile(r"<%--[\w\W]+?--%>")) # JSP

if not (techs_names == [] or libs_versions == []):
    # We convert the regex to string so we can compare them
    regex_list_repr = [regex.__repr__()[10:] for regex in regex_list]

    for tech, lib_v in zip(techs_names, libs_versions):
        if tech.lower() == "primefaces" or tech.lower() == "pf":

            # We check each version if it's inferior or superior and we removes tags accordingly
            if not(version.parse(lib_v) < version.parse("6.3")):
                # We search for the tags with an enumerator to get the index matchin the string
                indices = [indice for indice, string in enumerate(regex_list_repr) if "<p:tab" in string or "<p:commandButton" in string or "<p:carousel" in string or "<p:dataGrid" in string or "<p:dataList" in string or "<p:treeTable" in string or "<p:pickList" in string or "<p:progressBar" in string or "<p:slideMenu" in string or "<p:selectOneMenu" in string]
                # We then send the list if indices to our function that'll delete them from the original regex list
                delete_from_list(indices)
                
            if not(version.parse(lib_v) < version.parse("6.2.1")):
                indices = [indice for indice, string in enumerate(regex_list_repr) if "<p:inputTextarea" in string]
                delete_from_list(indices)

            # This version is a sepcial case because the "<p:button" tag is vulnerable in before both 6.1.16 and 6.0.29
            if not(version.parse(lib_v) < version.parse("6.1.16") and version.parse(lib_v) < version.parse("6.0.30")):
                if version.parse(lib_v) < version.parse("6.2.1") and version.parse(lib_v) < version.parse("6.0.30"):
                    indices = [indice for indice, string in enumerate(regex_list_repr) if "<p:button" in string]
                else:
                    indices = [indice for indice, string in enumerate(regex_list_repr) if "<p:inputTextarea" in string or "<p:button" in string]
                delete_from_list(indices)
            
            if not(version.parse(lib_v) < version.parse("6.0.7")):
                indices = [indice for indice, string in enumerate(regex_list_repr) if "<p:chart" in string]
                delete_from_list(indices)

            if not(version.parse(lib_v) < version.parse("6.0.2")):
                indices = [indice for indice, string in enumerate(regex_list_repr) if "<p:selectManyMenu" in string or "<p:fieldset" in string]
                delete_from_list(indices)

        elif tech.lower() == "jsf" :

            if not(version.parse(lib_v) < version.parse("2.2.6")):
                indices = [indice for indice, string in enumerate(regex_list_repr) if "<f:selectItems" in string]
                delete_from_list(indices)

exit()
if len(regex_list) == 0:
    print("[*] You're Regex List is empty [*]")

with open("TagList.txt", "w") as TagListFile:
    # Loop on every file on the list of pages
    for each_page in list_of_all_pages:
        # Open the file for read
        with open(each_page, "r", encoding="utf-8") as page:
            # Grab the content of the file as it is
            page_content = page.read()
            # Start looping through our regular expressions list
            for regex in regex_list:
                str_regex = regex.__repr__()[10:]
                try:
                    # Grab the result of the regex search, then we have two cases
                    list_of_tags = regex.findall(page_content)
                    
                    if list_of_tags != [] :
                        
                        # First Case : it's a "<p:selectMantMenu>" tag
                        if "p:selectManyMenu" in str_regex:
                            filtered_list = []
                            p_selectItems_regex = re.compile(r"<f:selectItems.*itemLabel.*\/>")
                            for elements in list_of_tags:
                                org_elements = elements
                                xss_itemLabel = elements.find('itemLabel')
                                if xss_itemLabel == -1:
                                    break
                                else:
                                    # We search for the attribute position then strip the start till the position 
                                    # Then search fro the end quote of the attribute and the we concatenate both ends
                                    # Example : <p:test attr="this the value" other="other value" />
                                    # Results : "this the value"
                                    elements = elements[xss_itemLabel + len("itemLabel") + 2:][:elements[xss_itemLabel
                                                + len("itemLabel") + 2:].find('"')]
                                
                                if "#{bundle" not in elements and "#{" in elements:
                                    elements = org_elements
                                    filtered_list.append(elements.strip("\n"))
                                
                            if filtered_list != []:
                                TagListFile.write("REGEX : " + str_regex + " \n\n")
                                TagListFile.write("You can find this in : " + each_page[len(pages_path):] + "\n\n")
                                for elements in filtered_list:
                                    TagListFile.write(elements + "\n")
                                TagListFile.write("\n\n")
                                TagListFile.write("-" * 20)
                                TagListFile.write("\n")
                        
                        # Second Case : "<p:selectOneMenu" tag
                        elif "p:selectOneMenu" in str_regex or "p:treeTable" in str_regex:
                            filtered_list = []
                            p_column_regex = re.compile(r"<p:column.*headerText.*/>")
                            for elements in list_of_tags:
                                org_elements = elements
                                xss_headerText = elements.find('headerText')
                                if xss_headerText == -1:
                                    break
                                else:
                                    elements = elements[xss_headerText + len("headerText") + 2:][:elements[xss_headerText
                                                + len("headerText") + 2:].find('"')]
                                
                                if "#{bundle" not in elements and "#{" in elements:
                                    elements = org_elements
                                    filtered_list.append(elements.strip("\n"))
                                
                            if filtered_list != []:
                                TagListFile.write("REGEX : " + str_regex + " \n\n")
                                TagListFile.write("You can find this in : " + each_page[len(pages_path):] + "\n\n")
                                for elements in filtered_list:
                                    TagListFile.write(elements + "\n")
                                TagListFile.write("\n\n")
                                TagListFile.write("-" * 20)
                                TagListFile.write("\n")
                            
                        # Third Case : Everything else
                        else:
                            filtered_list = []
                            for elements in list_of_tags:
                                # Save the original value of the "Tag"
                                org_elements = elements

                                # These boolean are added to explicitly add their related "tags" / "attributes" for further inspection, weather they contain dynamic data or not.

                                # This variable describe if there is a "<p:fileupload" tag
                                file_upload = False

                                # This variable describe if there is a "<p:dataExporter" tag
                                data_Exporter = False

                                # This varibale describe if there is a "transient" attribute set to "true"
                                transient_attribute = False

                                # This varibale describe if there is a "transient" attribute set to "true"
                                stackTrace_attribute = False

                                # This varibale describe if there is an (JSP, XHTML, HTML) comment
                                comment_attribute = False

                                if "transient=" in elements and "transient" in str_regex:
                                    # If the attribute is found we explicitly add it to the list for further inspection later
                                    filtered_list.append(elements.strip("\n"))
                                    # We set this to "True" to escape the the next check
                                    transient_attribute = True
                                
                                if "StackTrace".lower() in elements.lower() and "StackTrace" in str_regex:
                                    # If the word "StackTrace" is found we explicitly add it to the list for further inspection later
                                    filtered_list.append(elements.strip("\n"))
                                    # We set this to "True" to escape the the next check
                                    stackTrace_attribute = True
                                
                                if  "<%--" in str_regex or "<!--" in str_regex:
                                    # If the on of the comments is found we explicitly add it to the list for further inspection later
                                    filtered_list.append(elements.strip("\n"))
                                    # We set this to "True" to escape the the next check
                                    comment_attribute = True

                                elif "<p:tab" in elements or "<p:commandButton" in elements:
                                    xss_title = elements.find('title')
                                    if xss_title == -1:
                                        break
                                    else:
                                        elements = elements[xss_title + len("title") + 2:][:elements[xss_title
                                                    + len("title") + 2:].find('"')]
                                        
                                elif "<p:carousel" in elements:

                                    xss_headerText = elements.find('headerText')
                                    if xss_headerText == -1:
                                        elements_header = ""
                                    else:
                                        elements_header = elements[xss_headerText + len("headerText") + 2:][:elements[xss_headerText
                                                            + len("headerText") + 2:].find('"')]

                                    xss_footerText = elements.find('footerText')
                                    if xss_footerText == -1:
                                        elements_footer = ""
                                    else:
                                        elements_footer = elements[xss_footerText + len("footerText") + 2:][:elements[xss_footerText
                                                            + len("footerText") + 2:].find('"')]

                                    if elements_footer == "" and elements_header == "":
                                        break
                                    else:
                                        elements = elements_header + " - " + elements_footer   
                                
                                elif "<p:dataGrid" in elements or "<p:dataList" in elements or "<p:treeTable" in elements:
                                    xss_emptyMessage = elements.find('emptyMessage')
                                    if xss_emptyMessage == -1:
                                        break
                                    else:
                                        elements = elements[xss_emptyMessage + len("emptyMessage") + 2:][:elements[xss_emptyMessage
                                                    + len("emptyMessage") + 2:].find('"')]
                                        
                                elif "<p:pickList" in elements:
                                    xss_addLabel = elements.find('addLabel')
                                    if xss_addLabel == -1:
                                        break
                                    else:
                                        elements = elements[xss_addLabel + len("addLabel") + 2:][:elements[xss_addLabel
                                                    + len("addLabel") + 2:].find('"')]

                                elif "<p:slideMenu" in elements:
                                    xss_backLabel = elements.find('backLabel')
                                    if xss_backLabel == -1:
                                        break
                                    else:
                                        elements = elements[xss_backLabel + len("backLabel") + 2:][:elements[xss_backLabel
                                                    + len("backLabel") + 2:].find('"')]

                                elif "<p:inputTextarea" in elements:
                                    xss_completeMethod = elements.find('completeMethod')
                                    if xss_completeMethod == -1:
                                        elements_completeMethod = ""
                                    else:
                                        elements_completeMethod = elements[xss_completeMethod + len("completeMethod") + 2:][:elements[xss_completeMethod
                                                                    + len("completeMethod") + 2:].find('"')]

                                    xss_counterTemplate = elements.find('counterTemplate')
                                    if xss_counterTemplate == -1:
                                        elements_counterTemplate = ""
                                    else:
                                        elements_counterTemplate = elements[xss_counterTemplate + len("counterTemplate") + 2:][:elements[xss_counterTemplate
                                                                    + len("counterTemplate") + 2:].find('"')]

                                    if elements_counterTemplate == "" and elements_completeMethod == "":
                                        break
                                    else:
                                        elements = elements_completeMethod + " - " + elements_counterTemplate  
                                
                                elif "<p:progressBar" in elements:
                                    xss_labelTemplate = elements.find('labelTemplate')
                                    if xss_labelTemplate == -1:
                                        break
                                    else:
                                        elements = elements[xss_labelTemplate + len("labelTemplate") + 2:][:elements[xss_labelTemplate
                                                    + len("labelTemplate") + 2:].find('"')]

                                elif "<p:fieldset" in elements:
                                    xss_legend = elements.find('legend')
                                    if xss_legend == -1:
                                        break
                                    else:
                                        elements = elements[xss_legend + len("legend") + 2:][:elements[xss_legend
                                                    + len("legend") + 2:].find('"')]
                                                    
                                elif "<p:fileUpload" in elements:
                                    # If the tag is found we explicitly add it to the list for further inspection later
                                    filtered_list.append(elements.strip("\n"))
                                    # We set this to "True" to escape the the next check
                                    file_upload = True
                                
                                elif "<p:dataExporter" in elements:
                                    # If the tag is found we explicitly add it to the list for further inspection later
                                    filtered_list.append(elements.strip("\n"))
                                    # We set this to "True" to escape the the next check
                                    data_Exporter = True
                                
                                elif "<p:button" in elements:
                                    xss_href = elements.find('href')
                                    if xss_href == -1:
                                        elements_xss_href = ""
                                    else:
                                        elements_xss_href = elements[xss_href + len("href") + 2:][:elements[xss_href
                                                                    + len("href") + 2:].find('"')]

                                    xss_target = elements.find('target')
                                    if xss_target == -1:
                                        elements_target = ""
                                    else:
                                        elements_target = elements[xss_target + len("target") + 2:][:elements[xss_target
                                                                    + len("target") + 2:].find('"')]

                                    if elements_xss_href == "" and elements_target == "":
                                        break
                                    else:
                                        elements = elements_xss_href + " - " + elements_target  

                                # "Bundle" indicates data coming from the server (Not user controlled) 
                                # so we remove strings that contains it, and "#{" indicates dynamic data 
                                # (Maybe it's user controlled) so we keep it 
                                if "#{bundle" not in elements and "#{" in elements and (not file_upload and not data_Exporter and not transient_attribute and not stackTrace_attribute and not comment_attribute):
                                    elements = org_elements
                                    filtered_list.append(elements.strip("\n"))
                                
                            if filtered_list != []:
                                TagListFile.write("REGEX : " + str_regex + " \n\n")
                                TagListFile.write("You can find this in : " + each_page[len(pages_path):] + "\n\n")
                                for elements in filtered_list:
                                    TagListFile.write(elements + "\n")
                                TagListFile.write("\n\n")
                                TagListFile.write("-" * 20)
                                TagListFile.write("\n")

                except (NameError, ValueError, TypeError, FileExistsError, FileNotFoundError) as e:
                    print("[*] An ERROR Occurred [*]")
                    print(e)
