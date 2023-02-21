import base64
import requests
import datetime
import re
from prettytable import PrettyTable

"""
    General Helper Functions
"""


def filetime_to_datetime(filetime):
    """
        Translates date from file time format to datetime format
    ...

        Parameters
        ----------
        filetime : int
            Date in file time format

        Returns
        -------
        datetime
            filetime as datetime format

    """

    return datetime.datetime.utcfromtimestamp(filetime).replace(tzinfo=datetime.timezone.utc)


def reputation_calculator(rep, aggregator_type):
    """
        Gives understanding of reputation based on aggregator
    ...

        Parameters
        ----------
        rep : int
            reputation of hash, IPV4 address, or domain name
        aggregator_type : string
            vendor of specific reputation, as each have different scoring systems

        Returns
        -------
        string
            reputation along with insight

    """

    insight = ""                                        # additional information on rating

    match aggregator_type:

        # reputation based on VirusTotal scoring system
        case "VT":
            if rep <= -90:
                insight = "/-100 (fully malicious)"
            elif -90 < rep <= -70:
                insight = "/-100 (mostly malicious)"
            elif -70 < rep <= -50:
                insight = "/-100 (highly malicious)"
            elif -50 < rep <= -25:
                insight = "/-100 (somewhat malicious)"
            elif -25 < rep <= -5:
                insight = "/-100 (slightly malicious)"
            elif -5 < rep <= 5:
                insight = "/±100 (neither malicious nor harmless)"
            elif 5 < rep <= 25:
                insight = "/100 (slightly harmless)"
            elif 25 < rep <= 50:
                insight = "/100 (somewhat harmless)"
            elif 50 < rep <= 70:
                insight = "/100 (highly harmless)"
            elif 70 < rep <= 90:
                insight = "/100 (mostly harmless)"
            elif 90 < rep:
                insight = "/100 (fully harmless)"

        # reputation based on IBM's scoring system
        case "IBM":
            if rep < 2:
                insight = "/10 (fully harmless)"
            elif 2 <= rep < 3:
                insight = "/10 (mostly harmless)"
            elif 3 <= rep < 4:
                insight = "/10 (somewhat harmless)"
            elif 4 <= rep < 5:
                insight = "/10 (slightly harmless)"
            elif 5 <= rep < 6:
                insight = "/10 (neither malicious nor harmless)"
            elif 6 <= rep < 7:
                insight = "/10 (slightly malicious)"
            elif 7 <= rep < 8:
                insight = "/10 (somewhat malicious)"
            elif 8 <= rep < 9:
                insight = "/10 (mostly malicious)"
            elif 9 <= rep:
                insight = "/10 (fully malicious)"

    return str(rep) + insight


def read_keys(filename):
    """
          Reads API keys from text file
    ...

        Parameters
        ----------
        filename : string
            File to read from, including the path

        Returns
        -------
        vt_key
            API key used for VirusTotal queries
        IBM_key
            API key used for IBM X-Force queries
        IBM_pass
            API key password used for IBM X-Force queries
    """

    vt_key = None
    IBM_key = None
    IBM_pass = None

    # attempting to read from file
    try:

        with open(filename, mode="r", encoding="utf-8-sig") as txt_file:

            # stripping newlines from end of keys and storing them
            vt_key = txt_file.readline().strip()
            IBM_key = txt_file.readline().strip()
            IBM_pass = txt_file.readline().strip()

    # if an error occurs, prints useful information on error
    except Exception as e:

        if "PermissionError" in str(e.args):
            print("Error with permission reading file. If it is currently open, please close it and try again.")

        elif "IOError" in str(e.args):
            print("I/O error with ({0}) with " + filename + ": {1}".format(e.errorno, e.strerror))

        elif "UnicodeDecodeError" in str(e.args):
            print("Error reading from file, please ensure that file type is TXT.")

        elif "No such file or directory" in str(e.args):
            print("Error with finding file. If using absolute path, please ensure the path is correct.")

        else:
            print("Unknown error reading file keys. Additional information: " + str(e))

        exit(0)             # exiting program due to key error

    return vt_key, IBM_key, IBM_pass


def check_if_keys_work(vt_key, IBM_token):
    """
          Confirming API keys are correct by querying google.com and finding if any errors come up
    ...

        Parameters
        ----------
        vt_key : string
            VirusTotal API token
        IBM_token : string
            IBM X-Force Exchange Token

        Returns
        -------
        List
            List of key errors, if any exist
    """

    key_errors = []  # list of errors with given API keys

    """
        VirusTotal Key Check 
    """

    # relevant information for request
    headers = {
        "accept": "application/json",
        "x-apikey": vt_key
    }

    # Creating a VirusTotal request for Google's information
    url = "https://www.virustotal.com/api/v3/domains/google.com"
    response = requests.get(url, headers=headers).json()  # getting json object of HTTP response from VirusTotal

    # if there is an error in the response, there is an issue with VirusTotal's key
    if "error" in response:

        # if the specific error code is available, captures it
        if "code" in response["error"]:
            key_errors.append("VirusTotal: " + str(response["error"]["code"]))
        else:
            key_errors.append("VirusTotal: Incorrect credentials")

    """
        IBM Key Check
    """

    # relevant information for request
    headers = {
        "accept": "application/json",
        "Authorization": "Basic " + IBM_token
    }

    # Creating a IBM X-Force request for Google's information
    url = "https://api.xforce.ibmcloud.com/api/whois/google.com"
    response = requests.get(url, headers=headers).json()  # getting json object of HTTP response from IBM

    # if there is an error in the response, there is an issue with VirusTotal's key
    if "error" in response:
        key_errors.append("IBM X-Force: Incorrect credentials")

    return key_errors


def print_help_info():
    """
        Prints information on the program, including the description, prerequisites, and requirements
    """

    print("\nDESCRIPTION\n")
    print("\tThis program returns reputation information for files, domains, and IP addresses from multiple providers.")

    print("\nPREREQUISITES\n")
    print("\tVirusTotal API token (to acquire a token, "
          "see https://support.virustotal.com/hc/en-us/articles/115002100149-API")
    print("\tIBM API token and password (to acquire this set, see https://api.xforce.ibmcloud.com/doc/")

    print("\nREQUIREMENTS\n")
    print("\tTXT file with following format:")
    print(
        "\n\t\tLine 1 is VirusTotal's API Key\n\t\tLine 2 is IBM X-Force's API Key\n\t\tLine 3 is IBM X-Force's API "
        "Key Password")
    print("\n\tWhen searching: use IPV4 addresses, valid domain names, and a MD5, SHA-1, or SHA-256 file hash.\n")


"""
    VirusTotal functions
"""


def VirusTotal_get_general_information(info, response_attributes, simple_attributes, stored_names, link_search):
    """
        Adding general information on inputted VirusTotal search
    ...

        Parameters
        ----------
        info : Dictionary {string : string}
            current information on queried item
        response_attributes : Dictionary
            shorthand path to the query response's attributes
        simple_attributes : List [string]
            names of the simplest attributes to obtain from response attributes.
            ex: x = response_attribute[simple_attributes[0]]
        stored_names : List [string]
            names of the simple attributes to store in information for analysis and printing.
            ex: info[stored_names[0]]
        link_search : string
            addition to VirusTotal's main domain to generate link to full report

        Returns
        -------
        info : Dictionary {string : string}
            information on queried item with added information
    """

    # if the voting information of vendors is available, attempts to find and store harmless and malicious votes
    if "last_analysis_stats" in response_attributes:

        if "malicious" in response_attributes["last_analysis_stats"]:
            info["Malicious Votes"] = response_attributes["last_analysis_stats"]["malicious"]

        if "harmless" in response_attributes["last_analysis_stats"]:
            info["Harmless Votes"] = response_attributes["last_analysis_stats"]["harmless"]

        count = 0  # count of other votes

        # finding other vendors votes
        for rating, votes in response_attributes["last_analysis_stats"].items():
            if rating != "malicious" and rating != "harmless":
                count += votes
        info["Other Votes"] = count

        # if both malicious and harmless votes have been stored, finds the percentage of malicious votes
        if ("Harmless Votes" in info) and ("Malicious Votes" in info) and (
                info["Malicious Votes"] + info["Harmless Votes"] != 0):
            info["Percent of Votes as Malicious"] = str(
                round(info["Malicious Votes"] / (
                        info["Malicious Votes"] + info["Harmless Votes"] + info["Other Votes"]) * 100,
                      2)) + "%"

    # if the reputation of the domain is available, finds and stores it
    if "reputation" in response_attributes:
        info["reputation"] = reputation_calculator(response_attributes["reputation"], "VT")
    else:
        info["reputation"] = "N/A"

    # finding link to domain report
    info["link"] = "https://www.virustotal.com/gui/" + link_search

    """
        Adding specific information to search based on search type
    """

    # goes through each simple attribute and attempts to find information
    for index in range(len(simple_attributes)):

        # if the attribute is accessible, stores the information under its new name
        if simple_attributes[index] in response_attributes:
            info[stored_names[index]] = response_attributes[simple_attributes[index]]
        else:
            info[stored_names[index]] = "N/A"


def VirusTotal_domain(user_input, vt_key):
    """
        Queries VirusTotal for information on specific domain name
    ...

        Parameters
        ----------
        user_input : string
            user inputted domain name
        vt_key : string
            VirusTotal API token

        Returns
        -------
        dict
            VirusTotal information regarding user inputted domain name

    """

    # relevant information for request
    headers = {
        "accept": "application/json",
        "x-apikey": vt_key
    }

    # VirusTotal URL to request
    url = "https://www.virustotal.com/api/v3/domains/" + user_input

    response = requests.get(url, headers=headers).json()  # getting json object of HTTP response from VirusTotal
    info = {"name": "VirusTotal"}  # information from request to return

    # if there is an issue with response, stores error
    if "error" in response:
        info["summary"] = user_input + " not found."

    else:

        # shortening the path to relevant information, if available
        if ("data" in response) and ("attributes" in response["data"]):

            response_attributes = response["data"]["attributes"]  # attribute field where relevant information is stored

            # if the last certification date is available, finds and stores it
            if "last_https_certificate_date" in response_attributes:

                info["Last Certification Date"] = str(
                    filetime_to_datetime(
                        response_attributes["last_https_certificate_date"])).split(" ")[0]  # converting from filetime

                # if information on when the certification is available, finds and stores it
                if ("last_https_certificate" in response_attributes) \
                        and ("validity" in response_attributes["last_https_certificate"]) \
                        and ("not_after" in response_attributes["last_https_certificate"]["validity"]):
                    info["expires"] = response_attributes["last_https_certificate"]["validity"]["not_after"].split(" ")[
                        0]
                else:
                    info["expires"] = "N/A"

            else:
                info["expires"] = "N/A"

        # finding other general information such as voting information, reputation, and a link to the report
        VirusTotal_get_general_information(info, response_attributes, [], [], "domain/" + user_input)

    return info


def VirusTotal_IP(user_input, vt_key):
    """
        Queries VirusTotal for information on specific IPV4 address
    ...

        Parameters
        ----------
        user_input : string
            user inputted IPV4 address
        vt_key : string
            VirusTotal API token

        Returns
        -------
        dict
            VirusTotal information regarding user inputted IPV4 address

    """

    # relevant information for request
    headers = {
        "accept": "application/json",
        "x-apikey": vt_key
    }

    # VirusTotal URL to request
    url = "https://www.virustotal.com/api/v3/ip_addresses/" + user_input

    response = requests.get(url, headers=headers).json()  # getting json object of HTTP response from VirusTotal
    info = {"name": "VirusTotal"}  # information from request to return

    # if there is an issue with response, stores error
    if "error" in response:
        info["summary"] = user_input + " not found."

    else:

        # shortening the path to relevant information, if available
        if ("data" in response) and ("attributes" in response["data"]):
            response_attributes = response["data"]["attributes"]  # attribute field where relevant information is stored

            # finding other general information such as voting information, reputation, and a link to the report
            # IP information obtained: country of origin, owner of IP, continent,
            VirusTotal_get_general_information(info, response_attributes, ["country", "as_owner", "continent"],
                                               ["country", "owner", "Continent"], "ip-address/" + user_input)

    return info


def VirusTotal_hash(user_input, vt_key):
    """
        Queries VirusTotal for information on specific MD5, SHA1, or SHA256 hash
    ...

        Parameters
        ----------
        user_input : string
            user inputted MD5, SHA1, or SHA256 hash
        vt_key : string
            VirusTotal API token

        Returns
        -------
        dict
            VirusTotal information regarding user inputted MD5, SHA1, or SHA256 hash

    """

    # relevant information for request
    headers = {
        "accept": "application/json",
        "x-apikey": vt_key
    }

    # VirusTotal URL to request
    url = "https://www.virustotal.com/api/v3/files/" + user_input

    response = requests.get(url, headers=headers).json()  # getting json object of HTTP response from VirusTotal
    info = {"name": "VirusTotal"}  # information from request to return

    # if there is an issue with response, stores error
    if "error" in response:
        info["summary"] = user_input + " not found."

    else:

        # shortening the path to relevant information, if available
        if ("data" in response) and ("attributes" in response["data"]):

            response_attributes = response["data"]["attributes"]  # attribute field where relevant information is stored

            # if the date of the creation date of the file is available, finds and stores it as a string
            if "creation_date" in response_attributes:
                info["created"] = str(filetime_to_datetime(response_attributes["last_modification_date"])).split(" ")[0]
            else:
                info["created"] = "N/A"

            # if threat information is available on the current hash, finds and stores it
            if "popular_threat_classification" in response_attributes:

                # finds and stores the threat category of the current hash if available
                if "popular_threat_category" in response_attributes["popular_threat_classification"]:
                    info["category"] = \
                        response_attributes["popular_threat_classification"]["popular_threat_category"][0]["value"]
                else:
                    info["category"] = "N/A"

                # finds and stores the threat name of the current hash if available
                if "popular_threat_name" in response_attributes["popular_threat_classification"]:
                    info["Popular Name of File"] = \
                        response_attributes["popular_threat_classification"]["popular_threat_name"][0]["value"]

            else:
                info["category"] = "N/A"

            # if the language of the file is available, finds and stores it
            if ("pe_info" in response_attributes) and "resource_langs" in response_attributes["pe_info"]:
                for i, j in response_attributes["pe_info"]["resource_langs"].items():
                    info["Language"] = str(i).lower()
                    break

            # finding other general information such as voting information, reputation, and a link to the report
            # File information obtained: file type
            VirusTotal_get_general_information(info, response_attributes, ["type_description"], ["type"],
                                               "file/" + user_input)

    return info


"""
    IBM X-Force Methods
"""


def IBM_get_general_information(info, response, simple_attributes, stored_names):
    """
        Adding general information on inputted IBM X-Force search
    ...

        Parameters
        ----------
        info : Dictionary {string : string}
            current information on queried item
        response : Dictionary
            query response as json object
        simple_attributes : List [string]
            names of the simplest attributes to obtain from response attributes.
            ex: x = response_attribute[simple_attributes[0]]
        stored_names : List [string]
            names of the simple attributes to store in information for analysis and printing.
            ex: info[stored_names[0]]

        Returns
        -------
        info : Dictionary {string : string}
            information on queried item with added information
    """

    # goes through each simple attribute and attempts to find information
    for index in range(len(simple_attributes)):

        # if the attribute is accessible, stores the information under its new name
        if simple_attributes[index] in response:
            info[stored_names[index]] = response[simple_attributes[index]]
        else:
            info[stored_names[index]] = "N/A"


def IBM_domain(user_input, IBM_token):
    """
        Queries IBM X-Force for information on specific domain
    ...

        Parameters
        ----------
        user_input : string
            user inputted domain name
        IBM_token : string
            IBM X-Force API token

        Returns
        -------
        dict
            IBM X-Force information regarding user inputted domain name
    """

    # relevant information for request
    headers = {
        "accept": "application/json",
        "Authorization": "Basic " + IBM_token
    }

    # IBM URL to get Whois Info
    url = "https://api.xforce.ibmcloud.com/api/whois/" + user_input

    response = requests.get(url, headers=headers).json()  # getting json object of HTTP response from IBM

    info = {"name": "IBM X-Force"}  # information from request to return
    found = False  # flag for if information is found

    # if there is not an error, finds information
    if "error" not in response:

        found = True

        # if the date the domain was created is available, find and gets it
        if "createdDate" in response:
            info["Date Created"] = response["createdDate"].split("T")[0]

        # if the date the domain was last updated is available, find and gets it
        if "updatedDate" in response:
            info["Date of Last Update"] = response["updatedDate"].split("T")[0]

        # if the date the domain expires is available, find and gets it
        if "expiresDate" in response:
            info["expires"] = response["expiresDate"].split("T")[0]
        else:
            info["expires"] = "N/A"

    # if the general information on the domain was unable to be found, still adds it to report
    else:
        info["expires"] = "N/A"

    # IBM URL for obtaining their URL report
    url = "https://api.xforce.ibmcloud.com/api/url/" + user_input

    response = requests.get(url, headers=headers).json()  # getting json object of HTTP response from IBM

    # if there is no issue with obtaining the information, gets additional information
    if "error" not in response:

        found = True

        if "result" in response:

            # if there is a category of the website available, finds and gets it
            if "cats" in response["result"]:
                for i, j in response["result"]["cats"].items():
                    info["Website Category(s)"] = i
                    break

            # if IBM has scored the website, finds and gets it
            if "score" in response["result"]:
                info["reputation"] = reputation_calculator(response["result"]["score"], "IBM")
            else:
                info["reputation"] = "N/A"

    # if the general information on the domain was unable to be found, still adds it to report
    else:
        info["reputation"] = "N/A"

    # if the domain was unable to be found, states issue
    if not found:
        info.clear()
        info["summary"] = user_input + " not found."

    # if not, stores link to report
    else:
        info["link"] = "https://exchange.xforce.ibmcloud.com/url/" + user_input

    return info


def IBM_IP(user_input, IBM_token):
    """
        Queries IBM X-Force for information on specific IPV4 address
    ...

        Parameters
        ----------
        user_input : string
            user inputted IPV4 address
        IBM_token : string
            IBM X-Force API token

        Returns
        -------
        dict
            IBM X-Force information regarding user inputted IPV4 address
    """

    # relevant information for request
    headers = {
        "accept": "application/json",
        "Authorization": "Basic " + IBM_token
    }

    # IBM URL to get IP report
    url = "https://api.xforce.ibmcloud.com/api/ipr/" + user_input

    response = requests.get(url, headers=headers).json()  # getting json object of HTTP response from IBM

    info = {"name": "IBM X-Force"}  # information from request to return
    found = False  # flag for if information is found

    # if there is no issue with obtaining the information, gets additional information
    if "error" not in response:

        found = True

        # if the country of the IP address is available, finds and stores it
        if ("geo" in response) and ("country" in response["geo"]):
            info["country"] = response["geo"]["country"]
        else:
            info["country"] = "N/A"

        # if the catagory of the IP address is available, finds and stores it
        if "cats" in response:
            for i, j in response["cats"].items():
                info["Threat Category"] = i
                break
        else:
            info["Threat Category"] = "N/A"

        # if the score of the current domain is available, finds and stores it alongside information on the rating
        if "score" in response:
            info["reputation"] = reputation_calculator(response["score"], "IBM")
        else:
            info["reputation"] = "N/A"

        # finding other general information such as reputation
        # IP address information obtained: description of website
        IBM_get_general_information(info, response, ["reasonDescription"], ["Description"])

    # finding WHOIS info on IP address
    url = "https://api.xforce.ibmcloud.com/api/whois/" + user_input
    response = requests.get(url, headers=headers).json()
    if "error" not in response:

        found = True

        # if the owner of the IP address is available, finds and store sit
        if ("contact" in response) and ("organization" in response["contact"][0]):
            info["owner"] = response["contact"][0]["organization"]
        else:
            info["owner"] = "N/A"

    # if the IP address was unable to be found, states issue
    if not found:
        info["summary"] = user_input + " not found."

    # if not, stores link to report
    else:
        info["link"] = "https://exchange.xforce.ibmcloud.com/ip/" + user_input

    return info


def IBM_hash(user_input, IBM_token):
    """
        Queries IBM X-Force for information on specific MD5, SHA1, or SHA256 hash
    ...

        Parameters
        ----------
        user_input : string
            user inputted MD5, SHA1, or SHA256 hash
        IBM_token : string
            IBM X-Force API token

        Returns
        -------
        dict
            IBM X-Force information regarding user inputted MD5, SHA1, or SHA256 hash
    """

    # relevant information for request
    headers = {
        "accept": "application/json",
        "Authorization": "Basic " + IBM_token
    }

    # IBM URL to get IP report
    url = "https://api.xforce.ibmcloud.com/api/malware/" + user_input

    response = requests.get(url, headers=headers).json()  # getting json object of HTTP response from IBM

    info = {"name": "IBM X-Force"}  # information from request to return

    # if there is no issue with obtaining the information, gets additional information
    if "error" not in response:

        # shortening the path to relevant information, if available
        if ("malware" in response) and ("origins" in response["malware"]) and (
                "external" in response["malware"]["origins"]):

            external = response["malware"]["origins"][
                "external"]  # attribute field where relevant information is stored

            # if the risk score is available, finds and stores it
            if ("malware" in response) and ("risk" in response["malware"]):
                info["reputation"] = str(response["malware"]["risk"]).upper() + " Risk"
            else:
                info["reputation"] = "N/A"

            # finding other general information such as reputation
            # File information obtained: source of file, type of file, and platform of file
            IBM_get_general_information(info, external, ["source", "malwareType", "platform"],
                                        ["Source", "category", "type"])

            # if the date the file was first seen is available, finds and stores it
            if "firstSeen" in external:
                info["created"] = external["firstSeen"].split("T")[0]
            else:
                info["created"] = "N/A"

            # if the malware family of the file is available, finds and stores it
            if "family" in external and external["family"] is not None:
                info["Malware Family"] = external["family"][0]

        # if the risk score is available, finds and stores it
        if ("malware" in response) and ("risk" in response["malware"]):
            info["reputation"] = str(response["malware"]["risk"]).upper() + " Risk"
        else:
            info["reputation"] = "N/A"

        # if not, stores link to report
        info["link"] = "https://exchange.xforce.ibmcloud.com/malware/" + user_input

    # if the file was unable to be found, states issue
    else:
        info["summary"] = user_input + " not found."

    return info


"""
    General collection functions:
"""


def domain_info(user_input, vt_key, IBM_token):
    """
        Queries multiple reputation aggregators on a specific domain name and prints returned information in succinct table
    ...

        Parameters
        ----------
        user_input : string
            user inputted domain name
        vt_key : string
            VirusTotal API token
        IBM_token : string
            IBM X-Force API token
    """

    # link provided by Cisco Talos, whose API is currently unavailable
    talos = {"name": "Cisco Talos",
             "link": "https://talosintelligence.com/reputation_center/lookup?search=" + user_input}

    # grouping reported findings into single list
    info = [VirusTotal_domain(user_input, vt_key), IBM_domain(user_input, IBM_token), talos]

    headers = ["Aggregator", "Reputation", "Certificate Expiration Date", "Vendor Specific Information", "Link"]
    header_fields = ["name", "reputation", "expires", "link"]  # fields from header information

    t = PrettyTable(headers)  # creating table to print information into

    # goes through each vendor and prints information in their row
    for item in info:

        # if the request had an error, reports summary in link column
        if "summary" in item:
            t.add_row([item["name"], "", "", item["summary"], ""])

        # if the current item only has 2 items, it is the name and link to a report as their APIs are not available at this moment
        elif len(item) == 2:
            t.add_row([item["name"], "", "", "", item["link"]])

        # otherwise, prints information from the report
        else:
            vendor_specific = ""

            # goes through and adds all vendor specific information to one field, separated by a newline
            for name, value in item.items():
                if name not in header_fields:
                    vendor_specific += name + ": " + str(value) + "\n"
            t.add_row([item["name"], item["reputation"], item["expires"], vendor_specific, item["link"]])

    print(t)  # printing table


def ip_info(user_input, vt_key, IBM_token):
    """
        Queries multiple reputation aggregators on a specific IPV4 address and prints returned information in succinct table
    ...

        Parameters
        ----------
        user_input : string
            user inputted IPV4 Address
        vt_key : string
            VirusTotal API token
        IBM_token : string
            IBM X-Force API token
    """

    # link provided by Cisco Talos, whose API is currently unavailable
    talos = {"name": "Cisco Talos",
             "link": "https://talosintelligence.com/reputation_center/lookup?search=" + user_input}

    # grouping reported findings into single list
    info = [VirusTotal_IP(user_input, vt_key), IBM_IP(user_input, IBM_token), talos]

    headers = ["Aggregator", "Reputation", "Country", "Owner", "Vendor Specific Information", "Link"]
    header_fields = ["name", "reputation", "country", "owner", "link"]  # fields from header information

    t = PrettyTable(headers)  # creating table to print information into

    # goes through each vendor and prints information in their row
    for item in info:

        # if the request had an error, reports summary in link column
        if "summary" in item:
            t.add_row([item["name"], "", "", "", item["summary"], ""])

        # if the current item only has 2 items, it is the name and link to a report as their APIs are not available at this moment
        elif len(item) == 2:
            t.add_row([item["name"], "", "", "", "", item["link"]])

        # otherwise, prints information from the report
        else:
            vendor_specific = ""

            # goes through and adds all vendor specific information to one field, separated by newlines
            for name, value in item.items():
                if name not in header_fields:
                    vendor_specific += name + ": " + str(value) + "\n"
            t.add_row([item["name"], item["reputation"], item["country"], item["owner"], vendor_specific, item["link"]])

    print(t)  # printing table


def hash_info(user_input, vt_key, IBM_token, sha256_check):
    """
            Queries multiple reputation aggregators on a specific file hash and prints returned information in succinct table
        ...

            Parameters
            ----------
            user_input : string
                user inputted file hash
            vt_key : string
                VirusTotal API token
            IBM_token : string
                IBM X-Force API token
            sha256_check : object
                Object to check if the current hash is SHA256, to avoid linking to sites that do not process MD5 or SHA1 hashes
        """

    # link provided by Cisco Talos, whose API is currently unavailable
    talos = {"name": "Cisco Talos", "link": "https://talosintelligence.com/talos_file_reputation?s=" + user_input}

    # grouping reported findings into single list
    info = [VirusTotal_hash(user_input, vt_key), IBM_hash(user_input, IBM_token), talos]
    headers = ["Aggregator", "Reputation", "Malware Category", "File Type", "Date Created", "Vendor Specific " "Information", "Link"]
    header_fields = ["name", "reputation", "category", "type", "created", "link"]  # fields from header information

    t = PrettyTable(headers)  # creating table to print information into

    # goes through each vendor and prints information in their row
    for item in info:

        # if the request had an error, reports summary in link column
        if "summary" in item:
            t.add_row([item["name"], "", "", "", "", item["summary"], ""])

        # if the current item only has 2 items, it is the name and link to a report as their APIs are not available at this moment
        elif len(item) == 2:

            # only prints hashes that fit the sha256 requirement
            if sha256_check is not None:
                t.add_row([item["name"], "", "", "", "", "", item["link"]])

        # otherwise, prints information from the report
        else:
            vendor_specific = ""

            # goes through and adds all vendor specific information to one field, separated by a newline
            for name, value in item.items():
                if name not in header_fields:
                    vendor_specific += name + ": " + str(value) + "\n"
            t.add_row(
                [item["name"], item["reputation"], item["category"], item["type"], item["created"], vendor_specific,
                 item["link"]])

    print(t)  # printing table


def main():

    # Welcoming user with basic information
    print("Welcome to the Reputation Summarization Playbook!")

    file_name = input("Please enter text file with API tokens (include path and .txt), or type \"help\" for more "
                      "information: ")

    while file_name.casefold() == "help".casefold():
        print_help_info()
        file_name = input("Please enter text file with API tokens (include path and .txt), or type \"help\" for more "
                          "information: ")

    vt_key, IBM_key, IBM_pass = read_keys(file_name)            # obtaining API keys

    # if there was an issue obtaining the keys, prints error within read_keys and exits

    key_pass = (IBM_key + ":" + IBM_pass).encode("ascii")

    # if there are any issues with the inputted API keys, states issues

    IBM_token = str(base64.b64encode(key_pass))[2::][:-1]       # token needed to access IBM API

    key_errors = check_if_keys_work(vt_key, IBM_token)          # checking to see if inputted keys are valid

    # if there is any errors with the keys, prints errors and recommendations
    if len(key_errors) != 0:

        print("Issues with given API Keys:\n")

        for error in key_errors:
            print(error)

        print("\nPlease fix issues with keys within the given file.")
        print(
            "\nCorrect format:\nLine 1 is VirusTotal's API Key\nLine 2 is IBM X-Force's API Key\nLine 3 is IBM X-Force's API Key Password")
        exit(1)

    # otherwise, key reading was successful and keys used are correct

    print("Authentication Successful!\n")

    # Regex of accepted searches
    IPV4_regex = "^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    MD5_regex = "^[a-fA-F0-9]{32}$"
    SHA1_regex = "^[a-fA-F0-9]{40}$"
    SHA256_regex = "^[a-fA-F0-9]{64}$"
    domain_regex = "^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$"

    user_input = "not empty"  # user's current search

    # stating valid search options before first search
    print(
        "Valid search options include IPV4 addresses, domain names, MD5 hashes, SHA-1 hashes, and SHA-256 hashes.\n")

    # continues to query items until user enters blank line
    while user_input != "":

        # prompting user input
        user_input = input("Please enter your search, or enter a blank line to exit: ")
        print()

        # finding and printing information depending on type of input
        if re.search(IPV4_regex, user_input) is not None:
            ip_info(user_input, vt_key, IBM_token)
        elif re.search(domain_regex, user_input) is not None:
            domain_info(user_input, vt_key, IBM_token)
        elif (re.search(MD5_regex, user_input) is not None) or (re.search(SHA1_regex, user_input) is not None) \
                or (re.search(SHA256_regex, user_input) is not None):
            hash_info(user_input, vt_key, IBM_token, re.search(SHA256_regex, user_input))

        # if the user did not input a valid response, notifies them and reminds them of valid responses
        elif user_input != "":
            print(
                "Please enter a valid response (IPV4 address, domain name, MD5 hash, SHA-1 hash, or SHA-256 hash)")

        print() # creating some space before next search

    print("Goodbye!")  # printing goodbye message once user has finished their session


if __name__ == '__main__':
    main()
