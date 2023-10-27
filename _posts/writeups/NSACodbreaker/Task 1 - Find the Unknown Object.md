# Task 1  - Find the Unknown Object

```
The US Coast Guard (USCG) recorded an unregistered signal over 30 nautical miles away from the continental US (OCONUS). NSA is contacted to see if we have a record of a similar signal in our databases. The Coast guard provides a copy of the signal data. Your job is to provide the USCG any colluding records from NSA databases that could hint at the object’s location. Per instructions from the USCG, to raise the likelihood of discovering the source of the signal, they need multiple corresponding entries from the NSA database whose geographic coordinates are within 1/100th of a degree. Additionally, record timestamps should be no greater than 10 minutes apart.


Downloads:

    file provided by the USCG that contains metadata about the unknown signal (USCG.log)
    NSA database of signals (database.db)

Prompt:

    Provide database record IDs, one per line, that fit within the parameters specified above.
```

---
For This challenge we must find any signals in the NSA database that match to 1/100th of the coordinates of the unknown signal. So to start out we can just get an overview of the database with SQLite DB Viewer. 
![46dfc301afd24470f57841200b80ea80.png](../_resources/46dfc301afd24470f57841200b80ea80.png)
So we can see all the tables the most important ones for us right now are the location table. 
![7d011a521f45f0f48633e06bc9d73c43.png](../_resources/7d011a521f45f0f48633e06bc9d73c43.png)
Now all we need to do is select the ids from the location table where the lat and long is within 1/100th of the coordinates from the USCG log file. I wrote a simple python script to do this for me. 
[dbSearch.py]
The main piece of code that gets our relevant info fro the database is 
```
cursor.execute("SELECT id FROM location WHERE CAST(latitude as REAL) BETWEEN ? AND ? AND CAST(longitude as REAL) BETWEEN ? AND ?",
               (coordinates['lat'] - range_threshold, coordinates['lat'] + range_threshold,
                coordinates['long'] - range_threshold, coordinates['long'] + range_threshold))
```
Then we just take the outputed ids within the time frame from the log file and we are done !