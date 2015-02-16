I wrote this to sign XML messages rather than use xmlsec1 or similar C library because I was having trouble getting 
xmlsec1 to load on Windows from Go. This library does use the cgo to libxml2 for canonicalization, however it uses 
standard Go libraries for hashing and signing.