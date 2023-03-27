"""
COMP - Networking Systems Coursework1 Question 5

ALL code written, Commented and Tested by
Harry R J Softley-Graham
SN : 19087176

"""


import sys, socket
from dnslib import DNSRecord
from dnslib import QTYPE
import time


class AutoDig:
    """
    Class - AutoDIG

    This class performs the LNS quries in real time using the step by step method 
    as found within the UNIX and Linux terminal.

    If resolved it outputs the IP the address has been resolved to along with the
    commands to get that address

    If nothing is resolved it returns an error

    Initalise with the AutoDig Class
    To run use the RunAutoDig function
    """


    def __init__(self):

        """
        __init___

        The init class initialises perameters that are shared across functions.
        It also creates the socket for the DNS Quries along with the time out
        for a response.
        
        """

        #Deafult Root - Currently set to 198.41.04 - Operated by Verisign, Inc.
        self.ROOTNS_DN = "f.root-servers.net."
        self.ROOTNS_IN_ADDR = "198.41.0.4"

        #To set the Query Time Limit (set to 55 so it never exeeds 60 seconds)
        self.Query_Time_Limit = 55

        #To keep track of when the current Query Started
        self.Query_Start = 0

        #Socket to Query
        self.cs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.cs.settimeout(5)

        #Cache of DN and corralated IP addresses
        self.CACHE = {}


    def RunAutoDig(self,DNS_names):
        """
        RunAutoDig

        This function runs the auto dig program on a initalised class object

        Args:

            DNS_names - Array String - Takes an array of strings containing the
            DNS names to be resolved

        Output - It outputs in the console if a name has been resolved, with the
        corrisponding dig commands to get to the IP resolved
        """
        #Checks to see if the user has inputted a custom root address
        if len(sys.argv) == 2 or ((len(sys.argv) > 2 and sys.argv[1] != "-r")):
            DNS_names = DNS_names[1:]

        elif len(sys.argv) > 2 and sys.argv[1] == "-r": 
            New_Root_ADD =sys.argv[2]
            self.ROOTNS_IN_ADDR = New_Root_ADD
            DNS_names = DNS_names[3:]

        else:
            print("usage: {} [-r <DNS_root_IP_address>] <names_to_resolve>".format(sys.argv[0]))
            sys.exit()

        #Format inputted IP's to make sure a . is included at the end
        for index in range(len(DNS_names)):
            if DNS_names[index][-1] != ".":
                DNS_names[index] = DNS_names[index]+"."
                
        #Itrates through the inputted domain names and one by one querys them
        for input in DNS_names:
            self.Query_Start = time.time()

            try:
                self.Resolve_DNS_Name(input)
            except:
                print("Could not Resolve "+input+" - Input Error\n")


    def Resolve_DNS_Name(self,Name_Query):
        """
        Resolve_DNS_Name

        This function resolves an IP address to a provided inputted name server

        Args:

            Name_Query -  String - DN to be resolved

        """
        #Stops the function if time has been exeeded
        if time.time() >= self.Query_Start+self.Query_Time_Limit:
            return None
        
        #Sets current address
        Current_Address = self.Resolve_Cache(Name_Query)
        Current_Name = Name_Query

        #Looks to find the current address in the Cache (no LNS Querys required)
        try:
            Answer =self.CACHE[Current_Name][0]
            print("Resolved "+Name_Query+" at address "+Answer+"\n")

        #Executes the current LNS Query
        except:
            Answer = self.Query_DNS(Current_Name,Current_Address,Commands = [])

            #Checks the result, if nothing is found it alerts the user
            if Answer != None:
                print("Resolved "+Name_Query+" at address "+Answer[3])

                self.CACHE[Name_Query] = [str(Answer[3]),time.time()+Answer[2]]

                for Commands in Answer[4]:
                    print("dig "+Commands[0]+" +norecurse @"+Commands[1])
                print("")
            else:
                print("Could not Resolve "+Name_Query+" to a address\n")
        

    def Resolve_Cache(self,Name_Query):
        """
        Resolve_Cache

        This function runs the auto dig program on a initalised class object

        Args:

            Name_Query -  String - DN to be resolved

        Return:

            Current_IP - String - Highest level IP that is currently stored in cache,
                defults to the root address if nothing is found
        """
        #Sets the base IP address as the current root address
        Current_IP = self.ROOTNS_IN_ADDR

        #Splits then reconstructs the domain name
        Domains = Name_Query.split(".")
        Domains.pop(-1)
        Domain_To_Check = ""

        #Iterates backwards through the domain name to see what is in the Cache
        for Loop1 in range(len(Domains)):
            Domain_To_Check = Domains[-(Loop1+1)]+"."+Domain_To_Check

            try:
                Check = self.CACHE[Domain_To_Check]
            except:
                Check = None

            if Check == None:
                return Current_IP
            elif Check[1]<time.time():
                return Current_IP
            else:
                Current_IP = Check[0]

        #Default returns the root if there is nothing
        return Current_IP
        

    def Query_DNS(self,Name_Query,Address,Commands = []):
        """
        Resolve_Cache

        This function handles querying the DNS and getting the IP address

        Args:

            Name_Query -  String - DN to be resolved
            Address - String - Address to query if the DN is located there
            Commands - 2D Array - Array of commands that are printed when a
                name server is resolved 

        Return:

            Array - Returns an array containing infomation of the answer, and
            what IP the name server is located at. 
        """
        #Checks to see if the 60seconds time limit per query is over
        if time.time() > self.Query_Start+self.Query_Time_Limit:
                return None

        #Attempts to connect with the given address, if not it will wait 0.5 second before trying again
        try:
            query = DNSRecord.question(Name_Query)
            packet = query.pack()
            self.cs.sendto(packet,(Address,53))
            (response, _) =  self.cs.recvfrom(512)
        except:
            time.sleep(0.5)
            return self.Query_DNS(Name_Query,Address,Commands)


        #Receved response
        parsed_response = DNSRecord.parse(response)

        #Decomosing the recived response in to the question, answer, parsed_authorities and additional
        parsed_question = parsed_response.q
        parsed_answer = parsed_response.get_a()
        parsed_authorities = parsed_response.auth
        parsed_additionals = parsed_response.ar

        #Array to store formatted results
        Query_Results = []
        Query_Addtional = []

        #Formats the recived data in to 2D arrays within standard python variable types of strings and intigers
        for authorities in parsed_authorities:
            Query_Results.append([str(authorities.rname),QTYPE[authorities.rtype],int(authorities.ttl),str(authorities.rdata)])
        for additional in parsed_additionals:
            Query_Addtional.append([str(additional.rname),QTYPE[additional.rtype],int(additional.ttl),str(additional.rdata)])

        #Checks to see if a answer with a IP address has been recived, if so it returns the IP address
        if parsed_answer.rdata != None and QTYPE[parsed_answer.rtype] == "A":
            Commands.append([Name_Query,Address])
            self.CACHE[str(parsed_answer.rname)] = [str(parsed_answer.rdata),time.time()+int(parsed_answer.ttl)]

            #Returns a array of collected info in the form of, RNAME, RTYPE,TTL,RDATA,DIG COMMANDS to get to this point
            return [str(parsed_answer.rname),QTYPE[parsed_answer.rtype],int(parsed_answer.ttl),str(parsed_answer.rdata), Commands]

        #If a CNAME is found, it will instead 
        elif parsed_answer.rdata != None and QTYPE[parsed_answer.rtype] == "CNAME":
            #for answer in parsed_answer:
            Query_Results = []
            Query_Results.append([str(parsed_answer.rname),QTYPE[parsed_answer.rtype],int(parsed_answer.ttl),str(parsed_answer.rdata)])


        #Loop for iterating through the various responses that may contain an answer, if one route leads to a dead end or a SOA, it will try another route
        for Selected_Response in Query_Results:
            
            #Holding variable for linked data to the current response 
            Linked_Addtional = []

            #Iterates through the addtional data to find a response that has the same server name, and its given IPV4 address
            for index in range(len(Query_Addtional)):
                #Get relvent additional data
                if Selected_Response[3] == Query_Addtional[index][0] and (Query_Addtional[index][1] == "A"):
                    Linked_Addtional = Query_Addtional[index]
                    self.CACHE[str(Selected_Response[0])] = [str(Linked_Addtional[3]),time.time()+Selected_Response[2]]

            #Executes if the current chosen response is a CNAME
            if Selected_Response[1] == "CNAME":
                
                #Appends dig command to command array
                Commands.append([Name_Query,Address])
                #resolves the IP to see what is already stored in the CACHE
                Resolved_IP = self.Resolve_Cache(Selected_Response[3])

                #Sends a new Query with the new name
                New_Query = self.Query_DNS(Selected_Response[3],Resolved_IP,Commands)

                #If this route does not give a answer, it removes this from the list of commands and trys another route
                if New_Query != None:
                    return New_Query
                else:
                    Commands.pop(-1)

            #Exectutes if the selected is a name sever and there is a IPV4 address to this name server
            elif Selected_Response[1] == "NS" and Linked_Addtional != []:
                
                #Appends to the dig command array and sends a new query to this given DNS server
                Commands.append([Name_Query,Address])
                New_Query = self.Query_DNS(Name_Query,Linked_Addtional[3],Commands)

                #If there is no answer at the end of this route, it will remove this dig commands and try a new response
                if New_Query != None:
                    return New_Query
                else:
                    Commands.pop(-1)

            #Executes if there is a name server but there is no IP address given to the name server
            elif Selected_Response[1] == "NS" and Linked_Addtional == []:
                
                #Appends to the command and resolves the IP address to see where it will start when resolving this name servers IP
                Commands.append([Name_Query,Address])
                Resolved_IP = self.Resolve_Cache(Selected_Response[3])

                #Attempts to find the IP 
                Find_IP = self.Query_DNS(Selected_Response[3],Resolved_IP,Commands)
                
                #If not found it will remove the commands and attemp the next server
                if Find_IP != None:
                    Commands = Find_IP[4]
            
                    self.CACHE[Selected_Response[3]] = [Find_IP[3],time.time()+Selected_Response[2]]
                    return self.Query_DNS(Name_Query,Find_IP[3],Commands)
                else:
                    Commands.pop(-1)

            #Set to ignore SOA records
            elif Selected_Response[1] == "SOA":
                pass

        
        #If nothing is found or relevent it returns nothing
        return None


        

#Runs the Autodig when run in CMD
if __name__ == "__main__":
    Run = AutoDig()
    Run.RunAutoDig(sys.argv)
