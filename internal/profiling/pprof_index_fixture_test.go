package profiling

const pprofIndexPage = `<html><head><title>/debug/pprof/</title></head><body>
/debug/pprof/<br><p>Set debug=1 as a query parameter to export in legacy text format</p><br>
Types of profiles available:
<table><thead><td>Count</td><td>Profile</td></thead>
<tr><td>3</td><td><a href='allocs?debug=1'>allocs</a></td></tr>
<tr><td>12</td><td><a href='goroutine?debug=1'>goroutine</a></td></tr>
<tr><td>3</td><td><a href='heap?debug=1'>heap</a></td></tr>
<tr><td>0</td><td><a href='profile?debug=1'>profile</a></td></tr>
</table></body></html>`
