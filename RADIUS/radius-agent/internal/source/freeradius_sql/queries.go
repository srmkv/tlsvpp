package freeradius_sql

const (
	qRadcheck      = `SELECT username, attribute, op, value FROM radcheck ORDER BY username, id`
	qRadreply      = `SELECT username, attribute, op, value FROM radreply ORDER BY username, id`
	qRadgroupcheck = `SELECT groupname, attribute, op, value FROM radgroupcheck ORDER BY groupname, id`
	qRadgroupreply = `SELECT groupname, attribute, op, value FROM radgroupreply ORDER BY groupname, id`
	qRadusergroup  = `SELECT username, groupname, priority FROM radusergroup ORDER BY username, priority, groupname`
)
