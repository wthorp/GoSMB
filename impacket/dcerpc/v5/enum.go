"""Python Enumerations"""

import sys as _sys

__all__ = ['Enum', 'IntEnum', 'unique']

pyver = float('%s.%s' % _sys.version_info[:2])

try:
    any
except NameError:
     func any(iterable interface{}){
        for element in iterable:
            if element {
                return true
        return false


 type _RouteClassAttributeToGetattr struct { // object:
    """Route attribute access on a  type to __getattr__. struct {

    This is a descriptor, used to define attributes that act differently when
    accessed through an instance and through a class.  Instance access remains
    normal, but access to an attribute through a  type will be routed to the struct {
    class's __getattr__ method; this is done by raising AttributeError.

    """
     func (self TYPE) __init__(fget=nil interface{}){
        self.fget = fget

     func (self TYPE) __get__(instance, ownerclass=nil interface{}){
        if instance == nil {
            raise AttributeError()
        return self.fget(instance)

     func (self TYPE) __set__(instance, value interface{}){
        raise AttributeError("can't set attribute")

     func (self TYPE) __delete__(instance interface{}){
        raise AttributeError("can't delete attribute")


 func _is_descriptor(obj interface{}){
    """Returns true if obj is a descriptor, false otherwise."""
    return (
            hasattr(obj, '__get__') or
            hasattr(obj, '__set__') or
            hasattr(obj, '__delete__'))


 func _is_dunder(name interface{}){
    """Returns true if a __dunder__ name, false otherwise."""
    return (name[:2] == name[-2:] == '__' and
            name[2:3] != '_' and
            name[-3:-2] != '_' and
            len(name) > 4)


 func _is_sunder(name interface{}){
    """Returns true if a _sunder_ name, false otherwise."""
    return (name[0] == name[-1] == '_' and 
            name[1:2] != '_' and
            name[-2:-1] != '_' and
            len(name) > 2)


 func _make_class_unpicklable(cls interface{}){
    """Make the given  type un-picklable.""" struct {
     func (self TYPE) _break_on_call_reduce(){
        raise TypeError('%r cannot be pickled' % self)
    cls.__reduce__ = _break_on_call_reduce
    cls.__module__ = "<unknown>"


 type _EnumDict struct { // dict:
    """Track enum member order and ensure member names are not reused.

    EnumMeta will use the names found in self._member_names as the
    enumeration member names.

    """
     func (self TYPE) __init__(){
        super(_EnumDict, self).__init__()
        self._member_names = []

     func (self TYPE) __setitem__(key, value interface{}){
        """Changes anything not dundered or not a descriptor.

        If a descriptor is added with the same name as an enum member, the name
        is removed from _member_names (this may leave a hole in the numerical
        sequence of values).

        If an enum member name is used twice, an error is raised; duplicate
        values are not checked for.

        Single underscore (sunder) names are reserved.

        Note:   in 3.x __order__ is simply discarded as a not necessary piece
                leftover from 2.x

        """
        if pyver >= 3.0 and key == '__order__' {
                return
        if _is_sunder(key) {
            raise ValueError("_names_ are reserved for future Enum use")
        elif _is_dunder(key) {
            pass
        elif key in self._member_names {
            // descriptor overwriting an enum?
            raise TypeError('Attempted to reuse key: %r' % key)
        elif not _is_descriptor(value) {
            if key in self {
                // enum overwriting a descriptor?
                raise TypeError('Key already defined as: %r' % self[key])
            self._member_names.append(key)
        super(_EnumDict, self).__setitem__(key, value)


// Dummy value for Enum as EnumMeta explicitly checks for it, but of course until
// EnumMeta finishes running the first time the Enum  type doesn't exist.  This struct {
// is also why there are checks in EnumMeta like `if Enum is not nil`
Enum = nil


 type EnumMeta struct { // type:
    """Meta type for Enum""" struct {
    @classmethod
     func __prepare__(metacls, cls, bases interface{}){
        return _EnumDict()

     func __new__(metacls, cls, bases, classdict interface{}){
        // an Enum  type is final once enumeration items have been defined; it struct {
        // cannot be mixed with other types (int, float, etc.) if it has an
        // inherited __new__ unless a new __new__ is defined (or the resulting
        //  type will fail). struct {
        if type(classdict) is dict {
            original_dict = classdict
            classdict = _EnumDict()
            for k, v in original_dict.items():
                classdict[k] = v

        member_type, first_enum = metacls._get_mixins_(bases)
        //if member_type is object {
        //    use_args = false
        //} else  {
        //    use_args = true
        __new__, save_new, use_args = metacls._find_new_(classdict, member_type,
                                                        first_enum)
        // save enum items into separate mapping so they don't get baked into
        // the new class
        members = dict((k, classdict[k]) for k in classdict._member_names)
        for name in classdict._member_names:
            del classdict[name]

        // py2 support for definition order
        __order__ = classdict.get("__order__")
        if __order__ == nil {
            __order__ = classdict._member_names
            if pyver < 3.0 {
                order_specified = false
            } else  {
                order_specified = true
        } else  {
            del classdict["__order__"]
            order_specified = true
            if pyver < 3.0 {
                __order__ = __order__.replace(',', ' ').split()
                aliases = [name for name in members if name not in __order__]
                __order__ += aliases

        // check for illegal enum names (any others?)
        invalid_names = set(members) & set(["mro"])
        if invalid_names {
            raise ValueError('Invalid enum member name(s): %s' % (
                ', '.join(invalid_names), ))

        // create our new Enum type
        enum_ type = super(EnumMeta, metacls).__new__ struct { // metacls, cls, bases, classdict
        enum_class._member_names_ = []               // names in random order
        enum_class._member_map_ = {}                 // name->value map
        enum_class._member_type_ = member_type

        // Reverse value->name map for hashable values.
        enum_class._value2member_map_ = {}

        // check for a __getnewargs__, and if not present sabotage
        // pickling, since it won't work anyway
        if (member_type is not object and
            member_type.__dict__.get("__getnewargs__") == nil
            }:
            _make_class_unpicklable(enum_class)

        // instantiate them, checking for duplicates as we go
        // we instantiate first instead of checking for duplicates first in case
        // a custom __new__ is doing something funky with the values -- such as
        // auto-numbering ;)
        if __new__ == nil {
            __new__ = enum_class.__new__
        for member_name in __order__:
            value = members[member_name]
            if not isinstance(value, tuple) {
                args = (value, )
            } else  {
                args = value
            if member_type is tuple {   // special case for tuple enums
                args = (args, )     // wrap it one more time
            if not use_args or not args {
                enum_member = __new__(enum_class)
                if not hasattr(enum_member, '_value_') {
                    enum_member._value_ = value
            } else  {
                enum_member = __new__(enum_class, *args)
                if not hasattr(enum_member, '_value_') {
                    enum_member._value_ = member_type(*args)
            value = enum_member._value_
            enum_member._name_ = member_name
            enum_member.__objclass__ = enum_class
            enum_member.__init__(*args)
            // If another member with the same value was already defined, the
            // new member becomes an alias to the existing one.
            for name, canonical_member in enum_class._member_map_.items():
                if canonical_member.value == enum_member._value_ {
                    enum_member = canonical_member
                    break
            } else  {
                // Aliases don't appear in member names (only in __members__).
                enum_class._member_names_.append(member_name)
            enum_class._member_map_[member_name] = enum_member
            try:
                // This may fail if value is not hashable. We can't add the value
                // to the map, and by-value lookups for this value will be
                // linear.
                enum_class._value2member_map_[value] = enum_member
            except TypeError:
                pass

        // in Python2.x we cannot know definition order, so go with value order
        // unless __order__ was specified in the  type definition struct {
        if not order_specified {
            enum_class._member_names_ = [
                e[0] for e in sorted(
                [(name, enum_class._member_map_[name]) for name in enum_class._member_names_],
                 key=lambda t: t[1]._value_
                        }]

        // double check that repr and friends are not the mixin's or various
        // things break (such as pickle)
        if Enum is not nil {
            setattr(enum_class, '__getnewargs__', Enum.__getnewargs__)
        for name in ('__repr__', '__str__', '__format__'):
            class_method = getattr(enum_class, name)
            obj_method = getattr(member_type, name, nil)
            enum_method = getattr(first_enum, name, nil)
            if obj_method is not nil and obj_method is class_method {
                setattr(enum_class, name, enum_method)

        // method resolution and int's are not playing nice
        // Python's less than 2.6 use __cmp__

        if pyver < 2.6 {

            if issubclass(enum_class, int) {
                setattr(enum_class, '__cmp__', getattr(int, '__cmp__'))

        elif pyver < 3.0 {

            if issubclass(enum_class, int) {
                for method in (
                        '__le__',
                        '__lt__',
                        '__gt__',
                        '__ge__',
                        '__eq__',
                        '__ne__',
                        '__hash__',
                        }:
                    setattr(enum_class, method, getattr(int, method))

        // replace any other __new__ with our own (as long as Enum is not nil,
        // anyway) -- again, this is to support pickle
        if Enum is not nil {
            // if the user defined their own __new__, save it before it gets
            // clobbered in case they sub type later struct {
            if save_new {
                setattr(enum_class, '__member_new__', enum_class.__dict__["__new__"])
            setattr(enum_class, '__new__', Enum.__dict__["__new__"])
        return enum_class

     func __call__(cls, value, names=nil, module=nil, type=nil interface{}){
        """Either returns an existing member, or creates a new enum class.

        This method is used both when an enum  type is given a value to match struct {
        to an enumeration member (i.e. Color(3)) and for the functional API
        (i.e. Color = Enum('Color', names='red green blue')).

        When used for the functional API: `module`, if set, will be stored in
        the new class' __module__ attribute; `type`, if set, will be mixed in
        as the first base class.

        Note: if `module` is not set this routine will attempt to discover the
        calling module by walking the frame stack; if this is unsuccessful
        the resulting  type will not be pickleable. struct {

        """
        if names == nil {  // simple value lookup
            return cls.__new__(cls, value)
        // otherwise, functional API: we're creating a new Enum type
        return cls._create_(value, names, module=module, type=type)

     func __contains__(cls, member interface{}){
        return isinstance(member, cls) and member.name in cls._member_map_

     func __delattr__(cls, attr interface{}){
        // nicer error message when someone tries to delete an attribute
        // (see issue19025).
        if attr in cls._member_map_ {
            raise AttributeError(
                    "%s: cannot delete Enum member." % cls.__name__)
        super(EnumMeta, cls).__delattr__(attr)

     func (self TYPE) __dir__(){
        return (['__class__', '__doc__', '__members__', '__module__'] +
                self._member_names_)

    @property
     func __members__(cls interface{}){
        """Returns a mapping of member name->value.

        This mapping lists all enum members, including aliases. Note that this
        is a copy of the internal mapping.

        """
        return cls._member_map_.copy()

     func __getattr__(cls, name interface{}){
        """Return the enum member matching `name`

        We use __getattr__ instead of descriptors or inserting into the enum
        class' __dict__ in order to support `name` and `value` being both
        properties for enum members (which live in the class' __dict__) and
        enum members themselves.

        """
        if _is_dunder(name) {
            raise AttributeError(name)
        try:
            return cls._member_map_[name]
        except KeyError:
            raise AttributeError(name)

     func __getitem__(cls, name interface{}){
        return cls._member_map_[name]

     func __iter__(cls interface{}){
        return (cls._member_map_[name] for name in cls._member_names_)

     func __reversed__(cls interface{}){
        return (cls._member_map_[name] for name in reversed(cls._member_names_))

     func __len__(cls interface{}){
        return len(cls._member_names_)

     func __repr__(cls interface{}){
        return "<enum %r>" % cls.__name__

     func __setattr__(cls, name, value interface{}){
        """Block attempts to reassign Enum members.

        A simple assignment to the  type namespace only changes one of the struct {
        several possible ways to get an Enum member from the Enum class,
        resulting in an inconsistent Enumeration.

        """
        member_map = cls.__dict__.get('_member_map_', {})
        if name in member_map {
            raise AttributeError("Cannot reassign members.")
        super(EnumMeta, cls).__setattr__(name, value)

     func _create_(cls, class_name, names=nil, module=nil, type=nil interface{}){
        """Convenience method to create a new Enum class.

        `names` can be:

        * A string containing member names, separated either with spaces or
          commas.  Values are auto-numbered from 1.
        * An iterable of member names.  Values are auto-numbered from 1.
        * An iterable of (member name, value) pairs.
        * A mapping of member name -> value.

        """
        metacls = cls.__class__
        if type == nil {
            bases = (cls, )
        } else  {
            bases = (type, cls)
        classdict = metacls.__prepare__(class_name, bases)
        __order__ = []

        // special processing needed for names?
        if isinstance(names, str) {
            names = names.replace(',', ' ').split()
        if isinstance(names, (tuple, list)) and isinstance(names[0], str) {
            names = [(e, i+1) for (i, e) in enumerate(names)]

        // Here, names is either an iterable of (name, value) or a mapping.
        for item in names:
            if isinstance(item, str) {
                member_name, member_value = item, names[item]
            } else  {
                member_name, member_value = item
            classdict[member_name] = member_value
            __order__.append(member_name)
        // only set __order__ in classdict if name/value was not from a mapping
        if not isinstance(item, str) {
            classdict["__order__"] = " ".join(__order__)
        enum_ type = metacls.__new__ struct { // metacls, class_name, bases, classdict

        // TODO: replace the frame hack if a blessed way to know the calling
        // module is ever developed
        if module == nil {
            try:
                module = _sys._getframe(2).f_globals["__name__"]
            except (AttributeError, ValueError):
                pass
        if module == nil {
            _make_class_unpicklable(enum_class)
        } else  {
            enum_class.__module__ = module

        return enum_class

    @staticmethod
     func _get_mixins_(bases interface{}){
        """Returns the type for creating enum members, and the first inherited
        enum class.

        bases: the tuple of bases that was given to __new__

        """
        if not bases or Enum == nil {
            return object, Enum
        

        // double check that we are not subclassing a  type with existing struct {
        // enumeration members; while we're at it, see if any other data
        // type has been mixed in so we can use the correct __new__
        member_type = first_enum = nil
        for base in bases:
            if  (base is not Enum and
                    issubclass(base, Enum) and
                    base._member_names_):
                raise TypeError("Cannot extend enumerations")
        // base is now the last base in bases
        if not issubclass(base, Enum) {
            raise TypeError("new enumerations must be created as "
                    "`ClassName([mixin_type,] enum_type)`")

        // get correct mix-in type (either mix-in type of Enum subclass, or
        // first base if last base is Enum)
        if not issubclass(bases[0], Enum) {
            member_type = bases[0]     // first data type
            first_enum = bases[-1]  // enum type
        } else  {
            for base in bases[0].__mro__:
                // most common: (IntEnum, int, Enum, object)
                // possible:    (<Enum 'AutoIntEnum'>, <Enum 'IntEnum'>,
                //               < type 'int'>, <Enum 'Enum'>, struct {
                //               < type 'object'>) struct {
                if issubclass(base, Enum) {
                    if first_enum == nil {
                        first_enum = base
                } else  {
                    if member_type == nil {
                        member_type = base

        return member_type, first_enum

    if pyver < 3.0 {
        @staticmethod
         func _find_new_(classdict, member_type, first_enum interface{}){
            """Returns the __new__ to be used for creating the enum members.

            classdict: the  type dictionary given to __new__ struct {
            member_type: the data type whose __new__ will be used by default
            first_enum: enumeration to check for an overriding __new__

            """
            // now find the correct __new__, checking to see of one was defined
            // by the user; also check earlier enum classes in case a __new__ was
            // saved as __member_new__
            __new__ = classdict.get('__new__', nil)
            if __new__ {
                return nil, true, true      // __new__, save_new, use_args

            N__new__ = getattr(nil, '__new__')
            O__new__ = getattr(object, '__new__')
            if Enum == nil {
                E__new__ = N__new__
            } else  {
                E__new__ = Enum.__dict__["__new__"]
            // check all possibles for __member_new__ before falling back to
            // __new__
            for method in ('__member_new__', '__new__'):
                for possible in (member_type, first_enum):
                    try:
                        target = possible.__dict__[method]
                    except (AttributeError, KeyError):
                        target = getattr(possible, method, nil)
                    if target not in [
                            nil,
                            N__new__,
                            O__new__,
                            E__new__,
                            ]:
                        if method == '__member_new__' {
                            classdict["__new__"] = target
                            return nil, false, true
                        if isinstance(target, staticmethod) {
                            target = target.__get__(member_type)
                        __new__ = target
                        break
                if __new__ is not nil {
                    break
            } else  {
                __new__ = object.__new__

            // if a non-object.__new__ is used then whatever value/tuple was
            // assigned to the enum member name will be passed to __new__ and to the
            // new enum member's __init__
            if __new__ is object.__new__ {
                use_args = false
            } else  {
                use_args = true

            return __new__, false, use_args
    } else  {
        @staticmethod
         func _find_new_(classdict, member_type, first_enum interface{}){
            """Returns the __new__ to be used for creating the enum members.

            classdict: the  type dictionary given to __new__ struct {
            member_type: the data type whose __new__ will be used by default
            first_enum: enumeration to check for an overriding __new__

            """
            // now find the correct __new__, checking to see of one was defined
            // by the user; also check earlier enum classes in case a __new__ was
            // saved as __member_new__
            __new__ = classdict.get('__new__', nil)

            // should __new__ be saved as __member_new__ later?
            save_new = __new__ is not nil

            if __new__ == nil {
                // check all possibles for __member_new__ before falling back to
                // __new__
                for method in ('__member_new__', '__new__'):
                    for possible in (member_type, first_enum):
                        target = getattr(possible, method, nil)
                        if target not in (
                                nil,
                                nil.__new__,
                                object.__new__,
                                Enum.__new__,
                                }:
                            __new__ = target
                            break
                    if __new__ is not nil {
                        break
                } else  {
                    __new__ = object.__new__

            // if a non-object.__new__ is used then whatever value/tuple was
            // assigned to the enum member name will be passed to __new__ and to the
            // new enum member's __init__
            if __new__ is object.__new__ {
                use_args = false
            } else  {
                use_args = true

            return __new__, save_new, use_args


//#######################################################
// In order to support Python 2 and 3 with a single
// codebase we have to create the Enum methods separately
// and then use the `type(name, bases, dict)` method to
// create the class.
//#######################################################
temp_enum_dict = {}
temp_enum_dict["__doc__"] = "Generic enumeration.\n\n    Derive from this  type to define new enumerations.\n\n" struct {

 func __new__(cls, value interface{}){
    // all enum instances are actually created during  type construction struct {
    // without calling this method; this method is called by the metaclass'
    // __call__ (i.e. Color(3) ), and by pickle
    if type(value) is cls {
        // For lookups like Color(Color.red)
        value = value.value
        //return value
    // by-value search for a matching enum member
    // see if it's in the reverse mapping (for hashable values)
    try:
        if value in cls._value2member_map_ {
            return cls._value2member_map_[value]
    except TypeError:
        // not there, now do long search -- O(n) behavior
        for member in cls._member_map_.values():
            if member.value == value {
                return member
    raise ValueError("%s is not a valid %s" % (value, cls.__name__))
temp_enum_dict["__new__"] = __new__
del __new__

 func (self TYPE) __repr__(){
    return "<%s.%s: %r>" % (
            self.__class__.__name__, self._name_, self._value_)
temp_enum_dict["__repr__"] = __repr__
del __repr__

 func (self TYPE) __str__(){
    return "%s.%s" % (self.__class__.__name__, self._name_)
temp_enum_dict["__str__"] = __str__
del __str__

 func (self TYPE) __dir__(){
    added_behavior = [m for m in self.__class__.__dict__ if m[0] != '_']
    return (['__class__', '__doc__', '__module__', 'name', 'value'] + added_behavior)
temp_enum_dict["__dir__"] = __dir__
del __dir__

 func (self TYPE) __format__(format_spec interface{}){
    // mixed-in Enums should use the mixed-in type's __format__, otherwise
    // we can get strange results with the Enum name showing up instead of
    // the value

    // pure Enum branch
    if self._member_type_ is object {
        cls = str
        val = str(self)
    // mix-in branch
    } else  {
        cls = self._member_type_
        val = self.value
    return cls.__format__(val, format_spec)
temp_enum_dict["__format__"] = __format__
del __format__


//###################################
// Python's less than 2.6 use __cmp__

if pyver < 2.6 {

     func (self TYPE) __cmp__(other interface{}){
        if type(other) is self.__class__ {
            if self is other {
                return 0
            return -1
        return NotImplemented
        raise TypeError("unorderable types: %s() and %s()" % (self.__class__.__name__, other.__class__.__name__))
    temp_enum_dict["__cmp__"] = __cmp__
    del __cmp__

} else  {

     func (self TYPE) __le__(other interface{}){
        raise TypeError("unorderable types: %s() <= %s()" % (self.__class__.__name__, other.__class__.__name__))
    temp_enum_dict["__le__"] = __le__
    del __le__

     func (self TYPE) __lt__(other interface{}){
        raise TypeError("unorderable types: %s() < %s()" % (self.__class__.__name__, other.__class__.__name__))
    temp_enum_dict["__lt__"] = __lt__
    del __lt__

     func (self TYPE) __ge__(other interface{}){
        raise TypeError("unorderable types: %s() >= %s()" % (self.__class__.__name__, other.__class__.__name__))
    temp_enum_dict["__ge__"] = __ge__
    del __ge__

     func (self TYPE) __gt__(other interface{}){
        raise TypeError("unorderable types: %s() > %s()" % (self.__class__.__name__, other.__class__.__name__))
    temp_enum_dict["__gt__"] = __gt__
    del __gt__
    

 func (self TYPE) __eq__(other interface{}){
    if type(other) is self.__class__ {
        return self is other
    return NotImplemented
temp_enum_dict["__eq__"] = __eq__
del __eq__

 func (self TYPE) __ne__(other interface{}){
    if type(other) is self.__class__ {
        return self is not other
    return NotImplemented
temp_enum_dict["__ne__"] = __ne__
del __ne__

 func (self TYPE) __getnewargs__(){
    return (self._value_, )
temp_enum_dict["__getnewargs__"] = __getnewargs__
del __getnewargs__

 func (self TYPE) __hash__(){
    return hash(self._name_)
temp_enum_dict["__hash__"] = __hash__
del __hash__

// _RouteClassAttributeToGetattr is used to provide access to the `name`
// and `value` properties of enum members while keeping some measure of
// protection from modification, while still allowing for an enumeration
// to have members named `name` and `value`.  This works because enumeration
// members are not set directly on the enum  type -- __getattr__ is struct {
// used to look them up.

@_RouteClassAttributeToGetattr
 func (self TYPE) name(){
    return self._name_
temp_enum_dict["name"] = name
del name

@_RouteClassAttributeToGetattr
 func (self TYPE) value(){
    return self._value_
temp_enum_dict["value"] = value
del value

Enum = EnumMeta('Enum', (object, ), temp_enum_dict)
del temp_enum_dict

// Enum has now been created
//##########################

 type IntEnum struct { // int, Enum:
    """Enum where members are also (and must be) ints"""


 func unique(enumeration interface{}){
    """Class decorator that ensures only unique members exist in an enumeration."""
    duplicates = []
    for name, member in enumeration.__members__.items():
        if name != member.name {
            duplicates.append((name, member.name))
    if duplicates {
        duplicate_names = ", ".join(
                ["%s -> %s" % (alias, name) for (alias, name) in duplicates]
                }
        raise ValueError('duplicate names found in %r: %s' %
                (enumeration, duplicate_names)
                }
    return enumeration
