-- Dirbuster - Directory and File Enumeration Script
-- This script implements the core functionality of dirbuster for web directory enumeration

local http = require("socket.http")
local ltn12 = require("ltn12")
local socket = require("socket")

-- Configuration
local config = {
    target_url = "",
    wordlist_file = "wordlist.txt",
    threads = 10,
    timeout = 5,
    extensions = {".php", ".html", ".txt", ".js", ".css", ".xml", ".json", ".asp", ".aspx", ".jsp"},
    user_agent = "Dirbuster-Clone/1.0",
    follow_redirects = true,
    recursive = false,
    max_depth = 3,
    status_codes = {200, 301, 302, 403, 401}
}

-- Results storage
local results = {
    found = {},
    errors = {},
    total_requests = 0,
    start_time = 0
}

-- Wordlist management
local function load_wordlist(filename)
    local wordlist = {}
    local file = io.open(filename, "r")
    
    if not file then
        -- Default wordlist if file doesn't exist
        wordlist = {
            "admin", "administrator", "login", "test", "guest", "info", "adm", "mysql", "user",
            "administrator", "oracle", "ftp", "root", "bin", "nobody", "operator", "gopher",
            "backup", "www", "public", "upload", "temp", "tmp", "home", "users", "downloads",
            "images", "img", "css", "js", "javascript", "includes", "include", "assets",
            "static", "files", "file", "documents", "doc", "docs", "archive", "archives",
            "config", "configuration", "settings", "setup", "install", "installation",
            "database", "db", "data", "sql", "logs", "log", "cache", "session", "sessions",
            "private", "secret", "hidden", "internal", "system", "sys", "application", "app",
            "portal", "cms", "blog", "forum", "shop", "store", "cart", "checkout", "payment",
            "api", "webservice", "service", "services", "web", "site", "old", "new", "beta",
            "dev", "development", "staging", "production", "live", "demo", "example", "sample"
        }
        print("[!] Wordlist file not found, using default wordlist")
    else
        for line in file:lines() do
            line = line:gsub("^%s*(.-)%s*$", "%1") -- trim whitespace
            if line ~= "" and not line:match("^#") then -- skip empty lines and comments
                table.insert(wordlist, line)
            end
        end
        file:close()
        print("[+] Loaded " .. #wordlist .. " words from " .. filename)
    end
    
    return wordlist
end

-- HTTP request function
local function make_request(url, timeout)
    timeout = timeout or config.timeout
    local response_body = {}
    local headers = {
        ["User-Agent"] = config.user_agent,
        ["Accept"] = "*/*",
        ["Connection"] = "close"
    }
    
    local result, status_code, response_headers = http.request {
        url = url,
        headers = headers,
        sink = ltn12.sink.table(response_body),
        timeout = timeout
    }
    
    results.total_requests = results.total_requests + 1
    
    if result then
        local body = table.concat(response_body)
        return {
            status_code = status_code,
            headers = response_headers,
            body = body,
            size = #body
        }
    else
        return nil, status_code -- status_code contains error message
    end
end

-- Check if status code indicates a found resource
local function is_interesting_status(status_code)
    for _, code in ipairs(config.status_codes) do
        if status_code == code then
            return true
        end
    end
    return false
end

-- Format file size
local function format_size(bytes)
    if bytes < 1024 then
        return bytes .. "B"
    elseif bytes < 1024 * 1024 then
        return string.format("%.1fKB", bytes / 1024)
    else
        return string.format("%.1fMB", bytes / (1024 * 1024))
    end
end

-- Test a single path
local function test_path(base_url, path)
    local url = base_url .. "/" .. path
    local response, error = make_request(url)
    
    if response and is_interesting_status(response.status_code) then
        local result = {
            url = url,
            path = path,
            status_code = response.status_code,
            size = response.size,
            headers = response.headers
        }
        
        table.insert(results.found, result)
        
        local status_desc = ""
        if response.status_code == 200 then
            status_desc = "OK"
        elseif response.status_code == 301 or response.status_code == 302 then
            status_desc = "REDIRECT"
            if response.headers.location then
                status_desc = status_desc .. " -> " .. response.headers.location
            end
        elseif response.status_code == 403 then
            status_desc = "FORBIDDEN"
        elseif response.status_code == 401 then
            status_desc = "UNAUTHORIZED"
        end
        
        print(string.format("[%d] %-50s [%s] %s", 
            response.status_code, url, format_size(response.size), status_desc))
        
        return true
    elseif error then
        table.insert(results.errors, {path = path, error = error})
    end
    
    return false
end

-- Generate paths with extensions
local function generate_paths(wordlist)
    local paths = {}
    
    -- Add base words
    for _, word in ipairs(wordlist) do
        table.insert(paths, word)
    end
    
    -- Add words with extensions
    for _, word in ipairs(wordlist) do
        for _, ext in ipairs(config.extensions) do
            table.insert(paths, word .. ext)
        end
    end
    
    return paths
end

-- Progress display
local function show_progress(current, total)
    local percent = math.floor((current / total) * 100)
    local elapsed = os.time() - results.start_time
    local rate = current / elapsed
    local eta = (total - current) / rate
    
    io.write(string.format("\r[%d%%] %d/%d requests | Rate: %.1f req/s | ETA: %ds | Found: %d", 
        percent, current, total, rate, eta, #results.found))
    io.flush()
end

-- Main enumeration function
local function enumerate_directories(target_url, wordlist_file)
    print("[+] Starting directory enumeration")
    print("[+] Target: " .. target_url)
    print("[+] Wordlist: " .. (wordlist_file or config.wordlist_file))
    print("[+] Extensions: " .. table.concat(config.extensions, ", "))
    print("[+] Threads: " .. config.threads)
    print("[+] Timeout: " .. config.timeout .. "s")
    print("")
    
    -- Load wordlist
    local wordlist = load_wordlist(wordlist_file or config.wordlist_file)
    local paths = generate_paths(wordlist)
    
    print("[+] Generated " .. #paths .. " paths to test")
    print("[+] Starting enumeration...")
    print("")
    
    results.start_time = os.time()
    
    -- Test base URL first
    print("[+] Testing base URL...")
    test_path(target_url:gsub("/$", ""), "")
    
    -- Test all paths
    for i, path in ipairs(paths) do
        test_path(target_url:gsub("/$", ""), path)
        
        -- Show progress every 10 requests
        if i % 10 == 0 then
            show_progress(i, #paths)
        end
        
        -- Small delay to avoid overwhelming the server
        socket.sleep(0.01)
    end
    
    print("\n")
    print("[+] Enumeration completed!")
    print("[+] Total requests: " .. results.total_requests)
    print("[+] Found directories/files: " .. #results.found)
    print("[+] Errors: " .. #results.errors)
    
    -- Show summary
    if #results.found > 0 then
        print("\n[+] Found resources:")
        for _, result in ipairs(results.found) do
            print(string.format("  [%d] %s [%s]", 
                result.status_code, result.url, format_size(result.size)))
        end
    end
    
    if #results.errors > 0 then
        print("\n[!] Errors encountered:")
        for i, error in ipairs(results.errors) do
            if i <= 5 then -- Show only first 5 errors
                print("  " .. error.path .. ": " .. error.error)
            end
        end
        if #results.errors > 5 then
            print("  ... and " .. (#results.errors - 5) .. " more errors")
        end
    end
end

-- Export functions for use as a module
local dirbuster = {
    config = config,
    results = results,
    load_wordlist = load_wordlist,
    make_request = make_request,
    test_path = test_path,
    enumerate_directories = enumerate_directories
}

-- Command line interface
local function main(args)
    if not args or #args < 1 then
        print("Usage: lua dirbuster.lua <target_url> [wordlist_file]")
        print("Example: lua dirbuster.lua http://example.com wordlist.txt")
        return
    end
    
    local target_url = args[1]
    local wordlist_file = args[2]
    
    -- Validate URL
    if not target_url:match("^https?://") then
        print("[!] Error: Target URL must start with http:// or https://")
        return
    end
    
    config.target_url = target_url
    if wordlist_file then
        config.wordlist_file = wordlist_file
    end
    
    enumerate_directories(target_url, wordlist_file)
end

-- Run if called directly
if arg and arg[0] and arg[0]:match("dirbuster%.lua$") then
    main(arg)
end

return dirbuster