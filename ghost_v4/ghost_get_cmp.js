// Written for FieldFuzz
// Author: CedArctic
// Inspired by fridacov (https://github.com/DavidCatalan/fridacov).

// Use JS strict mode
"use strict";

// Intercepts ServerRegisterServiceHandler to get components
Interceptor.attach(ptr("%s"), {
    onEnter(args) {
        send({
            'cmp': 1,
            'context': JSON.stringify(this.context),
            'return_addr': this.returnAddress,
            'thread_id': this.threadId,
            'depth': this.depth,
            'error_number': this.err,
            'arg_1': args[0].toInt32(),
            'arg_2': args[1]
        })
    },
})