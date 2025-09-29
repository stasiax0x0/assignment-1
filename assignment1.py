
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