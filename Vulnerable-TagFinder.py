# -*- coding: utf-8 -*-
import argparse
import re
import os

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
parser = argparse.ArgumentParser(description='Vulnerable Tag Finder - Vulnerable Tags are always hidden until you look for them')

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

# If mojarra is < 2.2.6 this is vulnerable to XSS (Uncomment this if you're sure of the version of mojarra)
# regex_list.append(re.compile(r"<f:selectItems.*itemLabel.*>"))

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

# If "escape" is present and it's equal to "False" this is vulnerable to XSS
regex_list.append(re.compile(r"<.*escape=[\w\W]+?>"))

# Search for "DataExporter" component, to find if there is a CSV injection possibility
regex_list.append(re.compile(r"<p:dataExporter[\w\W]+?>"))

# Search for "transient" attribute, if it's equal to "true" then maybe this is vulnerable to CSRF
regex_list.append(re.compile(r"<.*transient.*>"))


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

                                if "transient=" in elements and "transient" in str_regex:
                                    # If the attribute is found we explicitly add it to the list for further inspection later
                                    filtered_list.append(elements.strip("\n"))
                                    # We set this to "True" to escape the the next check
                                    transient_attribute = True

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
                                if "#{bundle" not in elements and "#{" in elements and (not file_upload and not data_Exporter and not transient_attribute):
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
