from collections import defaultdict     #for creating a dictionary (with default default values) of lists
from datetime import datetime           #for parsing timestamps
from datetime import timedelta

LOGFILE= "sample_auth_small.log"
#1.	Parse log files line by line (files provided).

def parse_auth_line(line):              #function to parse a line from the auth log
    
    parts = line.split()                #split the line into parts
    # timestamp: first 3 tokens 'Mar 10 13:58:01'
    ts_str = " ".join(parts[0:3])
    try:
        ts = datetime.strptime(f"2025 {ts_str}", "%Y %b %d %H:%M:%S")       #parse the timestamp, assuming year 2025
    except Exception:                                                       #if parsing fails, set timestamp to None
        ts = None
    ip = None                                                               #initialize ip to None
    event_type = "other"                                                    #initialize event_type to "other"
    if "Failed password" in line:
        event_type = "failed"
    elif "Accepted password" in line or "Accepted publickey" in line:
        event_type = "accepted"
    if " from " in line:                                                    #look for the "from" token to find the IP address
        try:
            idx = parts.index("from")
            ip = parts[idx+1]
        except (ValueError, IndexError):                                    #if "from" not found or no token after it, set ip to None#
            ip = None
    return ts, ip, event_type


#2.  Detect and count failed login attempts, grouping by source IP.
#main script
if __name__ == "__main__":
    counts= defaultdict(int)
    per_ip_timestamps = defaultdict(list)                       #create a dictionary to store timestamps for each IP
    with open(LOGFILE) as f:                                #open the log file
        for line in f:                                      #read each line
            ts, ip, event = parse_auth_line(line)           #parse the line to get timestamp, ip, and event type
            if ip and event == "failed":                    #checks that ip is not null, and that event=="failed"
                counts[ip] += 1
            if ts:                                          #checks that ts is not null
                per_ip_timestamps[ip].append(ts)            #add the timestamp to the list for this IP
    print("Failed login attempts: ", dict(counts))
print("")

#3.	Identify possible brute-force attacks (≥ 5 failed logins from one IP within 10 minutes).

incidents = []                                                          #list to store detected brute-force incidents
window = timedelta(minutes=10)                                          #define the time window for detecting brute-force attempts (10 minutes)
for ip, times in per_ip_timestamps.items():                             #for each IP and its list of timestamps
    times.sort()                                                        #sort the timestamps
    n = len(times)                                                      #get the number of timestamps
    i = 0                                                               #initialize the start index
    while i < n:                                                        #scan through the timestamps for this IP
        j = i                                                           #initialize the end index
        while j + 1 < n and (times[j+1] - times[i]) <= window:          #expand the window: as long as the next timestamp is within 10 minutes of the first one in the current window
            j += 1                                                      #move the end index forward
        count = j - i + 1                                               #calculate the number of failed attempts in this window
        if count >= 5:                                                  #if there are 5 or more failed attempts in this window, record it as an incident
            incidents.append({                                          #add the incident details to the list
                "ip": ip,
                "count": count,
                "first": times[i].isoformat(),
                "last": times[j].isoformat()
            })
            # advance i past this cluster to avoid duplicate overlapping reports:
            i = j + 1
        else:                                                            #move to the next timestamp if no incident detected
            i += 1
# print incidents
print(f'Detected {len(incidents)} brute-force incidents {incidents}')


#4.	Output results into a structured report.

with open("report.txt", "w")as file:          #write the report to a file
    file.write("BRUTE FORCE INCIDENTS REPORT\n\n")
    file.write("Total failed login attempts per IP:\n")        #write hearder
    for ip, count in counts.items():
        file.write(f"    {ip}:  , {count} failed attempts\n")

    file.write(f'Detected {len(incidents)} brute-force incidents: \n\n') 
    for i, incidents in enumerate(incidents,1):
        file.write(f'Incident {i}: \n')
        file.write(f'IP: {incidents["ip"]}\n')
        file.write(f'Failed Attempts: {incidents["count"]}\n')
        file.write(f'Time Window: {incidents['first']} to {incidents['last']}\n\n')