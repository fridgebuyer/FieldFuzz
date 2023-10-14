// Written for FieldFuzz
// Author: CedArctic
// Inspired by fridacov (https://github.com/DavidCatalan/fridacov).

// Use JS strict mode
"use strict";


// Intercepts component functions and stalks their threads

// ModuleMap with only the base codesys binary in it
var filtered_maps = new ModuleMap(function (m) {
    if (m.path.indexOf('codesyscontrol.bin') != -1) { return true; }
    return false;
});

// Get the Codesys Module object
var codesys_module = filtered_maps.values()[0];
console.log('Codesys Module');
console.log('Path: ' + codesys_module.path);
console.log('Base: ' + codesys_module.base.toString());

// Parses a list of GumCompileEvents to extract basic blocks
function parse_bbs(bbs, fmaps) {
    
    // We need an array buffer to send back data using send(). Each basic block entry that will be placed 
    // inside the array buffer will contain a tuple with the basic block offset inside its module (4 bytes)
    // and the basic block size (2 bytes).

    // Size of an entry in bytes
    var entry_size = 8;

    // ArrayBuffer for the results
    var bb = new ArrayBuffer(bbs.length * entry_size);

    // Counter of number of entries
    var num_entries = 0;

    // Iterate through basic blocks
    for (var i = 0; i < bbs.length; i++) {
        var e = bbs[i];

        // Basic block start and end addresses
        var start = e[0];
        var end   = e[1];

        // Get path based on basic block start address and filter out 
        // basic blocks belonging to modules other than codesyscontrol.bin (e.g: libc)
        var path = fmaps.findPath(start);
        if (path == null) { continue; }

        // Basic block offset in codesyscontrol.bin module, basic block size
        var offset = start.sub(codesys_module.base).toInt32();
        var size = end.sub(start).toInt32();

        // Write results into ArrayBuffer. UintXXArray functions create pointers essentially.
        var x =  new Uint32Array(bb, num_entries * entry_size, 1);
        x[0] = offset;

        var y = new Uint16Array(bb, num_entries * entry_size + 4, 1);
        y[0] = size;

        num_entries++;
    }

    // Send back only the part of the ArrayBuffer that was filled
    return new Uint8Array(bb, 0, num_entries * entry_size);
}

// Stalker Trust Threshold: How many times a piece of code needs to be executed before 
// it is assumed it can be trusted to not mutate
Stalker.trustThreshold = 0;

console.log('Starting to stalk threads...');

// Dictionary to keep track of threads which stalker has already started stalking 
var stalked_threads = {};

// Functions to intercept so that we can stalk their threads
var func_address_book = %s;

// Configure Interceptor for each function in func_address_book
for(let i = 0; i < func_address_book.length; i++){

    Interceptor.attach(ptr(func_address_book[i]), {
        onEnter(args) {
            // console.log("Entered function");
            // console.log("Argument 1:", args[0].toInt32());
            
            // If the current thread is not being stalked, configure Stalker for it
            if(!(this.threadId in stalked_threads)){
                
                // Start stalking the thread
                console.log('=== Stalking thread ' + this.threadId + '. ===');

                stalked_threads[this.threadId] = true;

                Stalker.follow(this.threadId, {
                    // Enable listening on the compile event: when Stalker dynamically recompiles a basic block
                    events: {
                        compile: true
                    },
                    onReceive: function (event) {
                        // Event callback function called with `events` containing a binary blob
                        // comprised of one or more GumEvent structs. See FRIDA JS API docs.

                        // Parse GumEvent binary blob
                        var bb_events = Stalker.parse(event, {stringify: false, annotate: false});

                        // console.log('Got some events.');

                        // Parse and send back data to the Python side
                        var bbs = parse_bbs(bb_events, filtered_maps);
                        send({bbs: 1}, bbs);
                    }
                });
            }
        },
        onLeave(result) {
            // console.log('----------')
            // console.log('Exiting function on thread ' + this.threadId + '.')
        }
    });
}
