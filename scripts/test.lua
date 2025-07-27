-- Simple test script for rmap Lua integration
log("Starting test script for host: " .. HOST)

if PORT then
    log("Scanning port: " .. PORT)
    
    -- Simulate some port-specific logic
    if PORT == 80 then
        result = {
            service = "HTTP",
            method = "GET",
            status = "accessible"
        }
        output = "HTTP service detected on port 80"
    elseif PORT == 443 then
        result = {
            service = "HTTPS", 
            method = "SSL/TLS",
            status = "encrypted"
        }
        output = "HTTPS service detected on port 443"
    elseif PORT == 22 then
        result = {
            service = "SSH",
            method = "SSH-2.0",
            status = "secure"
        }
        output = "SSH service detected on port 22"
    else
        result = {
            service = "unknown",
            method = "tcp",
            status = "open"
        }
        output = "Unknown service on port " .. PORT
    end
else
    -- Host-level scan
    log("Performing host-level scan")
    result = {
        hostname = HOST,
        scan_type = "host_discovery",
        timestamp = os.date("%Y-%m-%d %H:%M:%S")
    }
    output = "Host-level scan completed for " .. HOST
end

log("Test script completed successfully")
