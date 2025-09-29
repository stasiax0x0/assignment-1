#part1
def ip_parser(line):            #define a function that has line as a parameter
    if " from " in line:        #if " from " is the line
        parts = line.split()    #splits the line in tokens and separates by space by default
        try:
            anchor = parts.index("from")     #find where from is -> this is the anchor
            ip = parts[anchor+1]            #the ip is the next token
            return ip.strip()               #remove any punctuation
 # gyat
        except (ValueError, IndexError):
            return None
        return None

#part2

from collections import defaultdict

counts = defaultdict(int)           #create a dictionary to keep track of ips

with open("sample_auth_small.log") as file:     #open and store sample_auth_small.log as file
    for line in file:
        if "Failed password" in line or "Invalid user" in line:     #if failed password or invalid user is in the line
            ip = ip_parser(line)        #extract ip by calling the function ip_parser
            if ip:                       #if the ip is the line
                counts[ip] +=1          #get the current count of the ip and add one to it
print(counts)