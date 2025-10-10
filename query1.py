import sqlite3
con = sqlite3.connect('remote_ssh_analysis.db')
c = con.cursor()
for r in c.execute("SELECT ts,host,action,user,ip,port FROM ssh_logs ORDER BY id DESC LIMIT 12"):
    print(r)
con.close()
