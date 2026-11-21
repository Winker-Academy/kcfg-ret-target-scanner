// WinDbg JavaScript: enumerate a module's Guard CF (KCFG) call targets.
// Usage: .scriptload C:\path\kcfg-scan.js
//        dx @$scriptContents.kcfg("nt")
//        dx @$scriptContents.kcfg("ci")  // tries C:\Windows\System32\CI.dll
//        dx @$scriptContents.kcfg("ci", "D:\\images\\CI.dll")

function main() {
    host.diagnostics.debugLog('Run: dx @$scriptContents.kcfg("nt")\n');
}

function invokeScript() {
    main();
}

function kcfg(moduleName, imagePath) {
    var log = host.diagnostics.debugLog;
    if (typeof moduleName !== "string" || !/^[A-Za-z0-9_.-]+$/.test(moduleName)) {
        log('Usage: dx @$scriptContents.kcfg("nt")\n');
        return;
    }

    var requested = moduleName.toLowerCase().replace(/\.(sys|dll|exe)$/, "");
    var ntNames = ["nt", "ntoskrnl", "ntkrnlmp", "ntkrnlpa", "ntkrpamp"];
    var control = host.namespace.Debugger.Utility.Control;
    var mod = null;
    var moduleContext = null;
    for (var candidate of host.currentProcess.Modules) {
        var name = String(candidate.Name).toLowerCase().replace(/\.(sys|dll|exe)$/, "");
        if (name === requested ||
            (requested === "nt" && ntNames.indexOf(name) !== -1)) {
            mod = candidate;
            moduleContext = candidate;
            break;
        }
    }
    if (mod === null) {
        // In KD, process.Modules can omit system-wide kernel modules shown by lm.
        var lmNames = requested === "nt" ? ntNames : [requested];
        for (var lmName of lmNames) {
            for (var lmLine of control.ExecuteCommand("lm m " + lmName)) {
                var match = /^\s*([0-9a-f`]+)\s+([0-9a-f`]+)\s+(\S+)/i.exec(String(lmLine));
                if (!match) continue;
                var listedName = match[3].toLowerCase().replace(/\.(sys|dll|exe)$/, "");
                if (listedName !== requested &&
                    !(requested === "nt" && ntNames.indexOf(listedName) !== -1))
                    continue;
                var listedBase = host.parseInt64(match[1].replace(/`/g, ""), 16);
                var listedEnd = host.parseInt64(match[2].replace(/`/g, ""), 16);
                mod = {
                    Name: match[3],
                    BaseAddress: listedBase,
                    Size: listedEnd.subtract(listedBase).asNumber()
                };
                break;
            }
            if (mod !== null) break;
        }
    }
    if (mod === null) {
        log("Module not loaded: " + moduleName + "\n");
        return;
    }

    var base = mod.BaseAddress;
    var imageSize = Number(mod.Size);
    var found = [];
    var scanned = 0;
    var unreadable = 0;
    var unreadableEntries = 0;
    var image = null;
    var fileBackedEntries = 0;
    var fileBackedTargets = 0;

    function hex(value) {
        var s = value.toString(16).replace(/^0x/i, "");
        return "0x" + s;
    }
    function readValues(address, count, size) {
        if (moduleContext !== null)
            return host.memory.readMemoryValues(address, count, size, false, moduleContext);
        return host.memory.readMemoryValues(address, count, size, false);
    }
    function bytesAt(address, count) {
        return readValues(address, count, 1);
    }
    function u16(address) {
        var b = bytesAt(address, 2);
        return b[0] + b[1] * 0x100;
    }
    function u32(address) {
        var b = bytesAt(address, 4);
        return (b[0] + b[1] * 0x100 + b[2] * 0x10000 + b[3] * 0x1000000) >>> 0;
    }
    function symbolAt(address) {
        try {
            var lines = control.ExecuteCommand('.printf "%y", ' + hex(address));
            var output = "";
            for (var line of lines) output += String(line).trim();
            return output || "<no symbol>";
        } catch (e) {
            return "<symbol lookup failed>";
        }
    }
    function byteString(bytes) {
        var parts = [];
        for (var i = 0; i < bytes.length; ++i) {
            parts.push(("0" + bytes[i].toString(16)).slice(-2).toUpperCase());
        }
        return parts.join(" ");
    }
    function fileU16(bytes, offset) {
        return bytes[offset] + bytes[offset + 1] * 0x100;
    }
    function fileU32(bytes, offset) {
        return (bytes[offset] + bytes[offset + 1] * 0x100 +
            bytes[offset + 2] * 0x10000 + bytes[offset + 3] * 0x1000000) >>> 0;
    }
    function loadImage(path, loadedTimestamp, loadedImageSize, loadedChecksum) {
        var fs = host.namespace.Debugger.Utility.FileSystem;
        var file = fs.OpenFile(path);
        var data = [];
        try {
            for (var b of file.ReadBytes(Number(file.Size))) data.push(b);
        } finally {
            file.Close();
        }
        if (data.length < 0x100 || fileU16(data, 0) !== 0x5a4d)
            throw new Error("invalid fallback PE file");
        var peOff = fileU32(data, 0x3c);
        if (peOff > data.length - 0x100 || fileU32(data, peOff) !== 0x4550)
            throw new Error("invalid fallback PE header");
        var fileOpt = peOff + 24;
        var fileMagic = fileU16(data, fileOpt);
        if (fileMagic !== magic ||
            fileU32(data, peOff + 8) !== loadedTimestamp ||
            fileU32(data, fileOpt + 0x38) !== loadedImageSize ||
            fileU32(data, fileOpt + 0x40) !== loadedChecksum)
            throw new Error("fallback image does not match loaded PE timestamp, size, checksum, or architecture");
        var sectionCount = fileU16(data, peOff + 6);
        var sectionOff = fileOpt + fileU16(data, peOff + 20);
        if (sectionOff + sectionCount * 40 > data.length)
            throw new Error("invalid fallback section headers");
        var sections = [];
        for (var s = 0; s < sectionCount; ++s) {
            var p = sectionOff + s * 40;
            sections.push({
                va: fileU32(data, p + 12),
                size: fileU32(data, p + 16),
                offset: fileU32(data, p + 20)
            });
        }
        return {
            read: function (rva, length) {
                var offset = -1;
                if (rva < fileU32(data, fileOpt + 0x3c)) offset = rva;
                for (var j = 0; j < sections.length && offset < 0; ++j) {
                    var sec = sections[j];
                    if (rva >= sec.va && rva - sec.va + length <= sec.size)
                        offset = sec.offset + rva - sec.va;
                }
                if (offset < 0 || offset + length > data.length)
                    throw new Error("RVA absent from fallback image");
                return data.slice(offset, offset + length);
            }
        };
    }
    try {
        if (u16(base) !== 0x5a4d) throw new Error("invalid DOS signature");
        var peOffset = u32(base.add(0x3c));
        if (peOffset < 0x40 || peOffset > imageSize - 0x100)
            throw new Error("invalid PE header offset");
        var pe = base.add(peOffset);
        if (u32(pe) !== 0x00004550) throw new Error("invalid PE signature");
        var timestamp = u32(pe.add(8));
        var optionalSize = u16(pe.add(20));
        var opt = pe.add(24);
        var magic = u16(opt);
        if (magic !== 0x20b && magic !== 0x10b)
            throw new Error("unsupported PE optional header");
        var dirOffset = magic === 0x20b ? 0x70 : 0x60;
        if (optionalSize < dirOffset + 11 * 8)
            throw new Error("load configuration directory is absent");
        var loadConfigRva = u32(opt.add(dirOffset + 10 * 8));
        var loadConfigSize = u32(opt.add(dirOffset + 10 * 8 + 4));
        var tableField = magic === 0x20b ? 0x80 : 0x50;
        var countField = magic === 0x20b ? 0x88 : 0x54;
        var flagsField = magic === 0x20b ? 0x90 : 0x58;
        if (!loadConfigRva || loadConfigSize < flagsField + 4 ||
            loadConfigRva > imageSize - flagsField - 4)
            throw new Error("Guard CF load configuration is absent");

        var config = base.add(loadConfigRva);
        var flags = u32(config.add(flagsField));
        var count = magic === 0x20b
            ? readValues(config.add(countField), 1, 8)[0]
            : u32(config.add(countField));
        var tableVa = readValues(config.add(tableField), 1, magic === 0x20b ? 8 : 4)[0];
        var extraBytes = flags >>> 28;
        var stride = 4 + extraBytes;

        var entryCount = magic === 0x20b ? count.asNumber() : count;
        if (!(flags & 0x400) || entryCount === 0) {
            log("No Guard CF function table in " + mod.Name + "\n");
            return;
        }
        if (extraBytes > 1)
            throw new Error("unsupported Guard CF metadata size: " + extraBytes);
        if (entryCount > Math.floor(imageSize / stride))
            throw new Error("Guard CF count exceeds image bounds");
        var table = magic === 0x20b ? tableVa : new host.Int64(tableVa);
        var tableRva = table.subtract(base);
        if (tableRva.compareTo(0) < 0 ||
            tableRva.add(entryCount * stride).compareTo(imageSize) > 0)
            throw new Error("Guard CF table lies outside the module");

        if (imagePath !== undefined) {
            if (typeof imagePath !== "string" || !imagePath)
                throw new Error("imagePath must be a PE file path string");
            image = loadImage(imagePath, timestamp, u32(opt.add(0x38)), u32(opt.add(0x40)));
            log("Fallback PE image verified: " + imagePath + "\n");
        } else {
            var diskNames = /\.(sys|dll|exe)$/i.test(mod.Name)
                ? [mod.Name]
                : [mod.Name + ".sys", mod.Name + ".dll", mod.Name + ".exe"];
            if (requested === "nt") diskNames.unshift("ntoskrnl.exe");
            var paths = [];
            // .scriptlist supplies the loaded script path, independent of WinDbg's working directory.
            try {
                for (var scriptLine of control.ExecuteCommand(".scriptlist")) {
                    var scriptMatch = /JavaScript script from '([^']*[\\/])kcfg-scan\.js'/i.exec(String(scriptLine));
                    if (!scriptMatch) continue;
                    for (var localName of diskNames)
                        paths.push(scriptMatch[1] + localName);
                    break;
                }
            } catch (scriptListError) {
                log("Script directory unavailable: " + scriptListError.message + "\n");
            }
            for (var currentName of diskNames) paths.push(currentName);
            for (var diskName of diskNames) {
                paths.push("C:\\Windows\\System32\\" + diskName);
                paths.push("C:\\Windows\\System32\\drivers\\" + diskName);
            }
            for (var path of paths) {
                try {
                    if (!host.namespace.Debugger.Utility.FileSystem.FileExists(path)) continue;
                    image = loadImage(path, timestamp, u32(opt.add(0x38)), u32(opt.add(0x40)));
                    log("Fallback PE image verified: " + path + "\n");
                    break;
                } catch (imageError) {
                    log("Fallback PE image rejected: " + path + " (" + imageError.message + ")\n");
                }
            }
        }

        log("KCFG targets: " + mod.Name + " (" + entryCount + " entries)\n");
        for (var i = 0; i < entryCount; ++i) {
            var entry = table.add(i * stride);
            var rva;
            var flagsByte;
            var entrySource = "";
            try {
                rva = u32(entry);
                flagsByte = extraBytes ? bytesAt(entry.add(4), 1)[0] : 0;
            } catch (e) {
                if (image !== null) {
                    try {
                        var fileEntry = image.read(tableRva.asNumber() + i * stride, stride);
                        rva = fileU32(fileEntry, 0);
                        flagsByte = extraBytes ? fileEntry[4] : 0;
                        entrySource = " [table: file]";
                        ++fileBackedEntries;
                    } catch (fileError) { /* report the unreadable entry below */ }
                }
            }
            if (rva === undefined) {
                // A kernel minidump may omit some pages of the image's GFIDS table.
                var skip = Math.min(entryCount - i,
                    Math.ceil((0x1000 - (entry.getLowPart() & 0xfff)) / stride));
                unreadableEntries += skip;
                log("[" + i + ".." + (i + skip - 1) + "] GFIDS table page unreadable at " +
                    hex(entry) + "\n");
                i += skip - 1;
                continue;
            }
            if (rva >= imageSize) {
                log("[" + i + "] invalid RVA " + hex(rva) + "\n");
                continue;
            }
            var target = base.add(rva);
            var symbol = symbolAt(target);
            var suffix = flagsByte ? " [GFIDS flags=" + hex(flagsByte) + "]" : "";
            suffix += entrySource;
            ++scanned;
            try {
                var bytes;
                var targetSource = "";
                try {
                    bytes = bytesAt(target, 8);
                } catch (memoryError) {
                    if (image === null) throw memoryError;
                    bytes = image.read(rva, 8);
                    targetSource = " [bytes: file]";
                    ++fileBackedTargets;
                }
                var hasRet = false;
                for (var j = 0; j < 8; ++j) {
                    if (bytes[j] === 0xc3) { hasRet = true; break; }
                }
                var row = hex(target) + "  " + symbol + suffix + targetSource;
                if (hasRet) {
                    row += "  [FOUND!  " + byteString(bytes) + "]";
                    found.push(row);
                }
                log(row + "\n");
            } catch (e) {
                ++unreadable;
                log(hex(target) + "  " + symbol + suffix + "  <8 bytes unreadable>\n");
            }
        }
        log("\nFOUND RECAP (" + found.length + "/" + scanned +
            "; unreadable targets=" + unreadable +
            "; unreadable table entries=" + unreadableEntries +
            "; file entries=" + fileBackedEntries +
            "; file target bytes=" + fileBackedTargets + ")\n");
        for (var k = 0; k < found.length; ++k) log(found[k] + "\n");
    } catch (e) {
        log("KCFG scan failed for " + mod.Name + ": " + e.message + "\n");
    }
}
