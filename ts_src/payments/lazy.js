"use strict";
exports.__esModule = true;
function prop(object, name, f) {
    Object.defineProperty(object, name, {
        configurable: true,
        enumerable: true,
        get: function () {
            var _value = f.call(this);
            this[name] = _value;
            return _value;
        },
        set: function (_value) {
            Object.defineProperty(this, name, {
                configurable: true,
                enumerable: true,
                value: _value,
                writable: true
            });
        }
    });
}
exports.prop = prop;
function value(f) {
    var _value;
    return function () {
        if (_value !== undefined)
            return _value;
        _value = f();
        return _value;
    };
}
exports.value = value;
