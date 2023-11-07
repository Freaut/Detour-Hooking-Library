local ffi       = require("ffi")
local cast      = ffi.cast
local typeof    = ffi.typeof
local old_find_signature = client.find_signature

client.find_signature = function(module, pattern, offset)
    local sig = old_find_signature(module, pattern)
    offset = offset or 0
    if sig then
        return ffi.cast("uintptr_t", sig) + offset
    end
end

local jmp_ecx               = client.find_signature("engine.dll", "\xFF\xE1")
local get_proc_addr         = cast("uint32_t**", cast("uint32_t", client.find_signature("engine.dll", "\xFF\x15\xCC\xCC\xCC\xCC\xA3\xCC\xCC\xCC\xCC\xEB\x05")) + 2)[0][0]
local fn_get_proc_addr      = cast("uint32_t(__fastcall*)(unsigned int, unsigned int, uint32_t, const char*)", jmp_ecx)
local get_module_handle     = cast("uint32_t**", cast("uint32_t", client.find_signature("engine.dll", "\xFF\x15\xCC\xCC\xCC\xCC\x85\xC0\x74\x0B")) + 2)[0][0]
local fn_get_module_handle  = cast("uint32_t(__fastcall*)(unsigned int, unsigned int, const char*)", jmp_ecx)

local function proc_bind(module_name, function_name, typedef)
    local ctype = typeof(typedef)
    local module_handle = fn_get_module_handle(get_module_handle, 0, module_name)
    local proc_address = fn_get_proc_addr(get_proc_addr, 0, module_handle, function_name)
    local call_fn = cast(ctype, jmp_ecx)

    return function(...)
        return call_fn(proc_address, 0, ...)
    end
end

local native_virtualprotect = proc_bind(
    "kernel32.dll",
    "VirtualProtect",
    "int(__fastcall*)(unsigned int, unsigned int, void* lpAddress, unsigned long dwSize, unsigned long flNewProtect, unsigned long* lpflOldProtect)"
)

local function copy(dst, src, len)
    return ffi.copy(cast("void*", dst), cast("const void*", src), len)
end

local function virtualprotect(lpAddress, dwSize, flNewProtect, lpflOldProtect)
    return native_virtualprotect(cast("void*", lpAddress), dwSize, flNewProtect, lpflOldProtect)
end

local detour = {
    hooks = {}
}

function detour.new(typedef, callback, hook_addr, size)
    local size = size or 5
    local hook, mt = {}, {}
    local old_prot = ffi.new("unsigned long[1]")
    local org_bytes = ffi.new("uint8_t[?]", size)
    copy(org_bytes, hook_addr, size)
    local detour_addr = tonumber(cast('intptr_t', cast('void*', cast(typedef, callback))))

    hook.call = cast(typedef, hook_addr)
    mt = {
        __call = function(self, ...)
            self.stop()
            local res = self.call(...)
            self.start()
            return res
        end
    }

    local hook_bytes = ffi.new("uint8_t[?]", size, 0x90)
    hook_bytes[0] = 0xE9
    cast("int32_t*", hook_bytes + 1)[0] = (detour_addr - hook_addr - 5)
    hook.status = false

    local function set_status(bool)
        hook.status = bool

        virtualprotect(hook_addr, size, 0x40, old_prot)
        copy(hook_addr, bool and hook_bytes or org_bytes, size)
        virtualprotect(hook_addr, size, old_prot[0], old_prot)
    end

    hook.stop   = function() set_status(false) end
    hook.start  = function() set_status(true) end

    hook.start()
    
    table.insert(detour.hooks, hook)

    return setmetatable(hook, mt)
end

function detour.unhook_all()
    for _, hook in pairs(detour.hooks) do
        hook.stop()
    end
end

client.set_event_callback("shutdown", detour.unhook_all)

-- Example usage
--[[
function CSA(thisptr, edx)
    CSA(thisptr, edx)

    print("Hello")
end

local updateCSA = client.find_signature("client.dll", "\x8B\xF1\x80\xBE\xCC\xCC\xCC\xCC\xCC\x74\x36", - 5)
CSA = detour.new('void(__fastcall*)(void*, void*)', CSA, updateCSA)
]]