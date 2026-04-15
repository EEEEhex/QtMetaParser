"""
QtMetaParser - Qt5/Qt6 MetaObject parser for IDA Pro
Supports: Qt5 (revision 7-8) and Qt6 (revision 9-13+)
Compatible with: IDA 9.x (no dependency on removed ida_struct)

Usage:
  - Place cursor on QMetaObject::Data (staticMetaObject) in IDA
  - Run via Alt+; or Edit > Plugins > QtMetaParser
  - Script parses and annotates all methods, signals, slots with comments

References:
  - https://www.52pojie.cn/forum.php?mod=viewthread&tid=497018
  - https://codebrowser.dev/qt6/qtbase/src/corelib/kernel/qmetaobject.cpp.html
"""

import idc
import idaapi
import ida_bytes
import ida_ida
import ida_name
import ida_kernwin
import ida_idaapi
import ida_segment

# --------------------------------------------------------------------------
# Architecture detection
# --------------------------------------------------------------------------
ADDR_SZ = 8 if ida_ida.inf_is_64bit() else 4
MAX_EA = ida_ida.inf_get_max_ea()

FF_DWORD = ida_bytes.FF_DWORD
FF_QWORD = ida_bytes.FF_QWORD
FF_DATA = ida_bytes.FF_DATA
BADADDR = ida_idaapi.BADADDR

if ADDR_SZ == 8:
    ARCH_F = FF_QWORD | FF_DATA
    read_addr = idc.get_qword
else:
    ARCH_F = FF_DWORD | FF_DATA
    read_addr = idc.get_wide_dword

read_dword = idc.get_wide_dword

# --------------------------------------------------------------------------
# QMetaType name mapping (Qt5 & Qt6 common)
# --------------------------------------------------------------------------
QMETATYPE_MAP = {
    0: "UnknownType",
    1: "Bool", 2: "Int", 3: "UInt", 4: "LongLong", 5: "ULongLong",
    6: "Double", 7: "QChar", 8: "QVariantMap", 9: "QVariantList",
    10: "QString", 11: "QStringList", 12: "QByteArray", 13: "QBitArray",
    14: "QDate", 15: "QTime", 16: "QDateTime", 17: "QUrl", 18: "QLocale",
    19: "QRect", 20: "QRectF", 21: "QSize", 22: "QSizeF",
    23: "QLine", 24: "QLineF", 25: "QPoint", 26: "QPointF",
    27: "QRegExp", 28: "QVariantHash", 29: "QEasingCurve", 30: "QUuid",
    31: "VoidStar", 32: "Long", 33: "Short", 34: "Char",
    35: "ULong", 36: "UShort", 37: "UChar", 38: "Float",
    39: "QObjectStar", 40: "SChar", 41: "QVariant", 42: "QModelIndex",
    43: "Void", 44: "QRegularExpression",
    45: "QJsonValue", 46: "QJsonObject", 47: "QJsonArray", 48: "QJsonDocument",
    49: "QByteArrayList", 50: "QCborValue", 51: "QCborArray", 52: "QCborMap",
    53: "QCborSimpleType",
    64: "QFont", 65: "QPixmap", 66: "QBrush", 67: "QColor",
    68: "QPalette", 69: "QIcon", 70: "QImage", 71: "QPolygon",
    72: "QRegion", 73: "QBitmap", 74: "QCursor", 75: "QKeySequence",
    76: "QPen", 77: "QTextLength", 78: "QTextFormat",
    79: "QMatrix", 80: "QTransform", 81: "QMatrix4x4",
    82: "QVector2D", 83: "QVector3D", 84: "QVector4D", 85: "QQuaternion",
    86: "QPolygonF", 87: "QColorSpace",
    121: "QSizePolicy",
    1024: "User",
    65536: "User",
}

METHOD_TYPE_DICT = {0x00: "METHOD", 0x04: "SIGNAL", 0x08: "SLOT", 0x0c: "CONSTRUCTOR"}
METHOD_ACCESS_DICT = {0x00: "Private", 0x01: "Protected", 0x02: "Public"}

IS_UNRESOLVED_TYPE = 0x80000000
TYPE_NAME_INDEX_MASK = 0x7FFFFFFF


# --------------------------------------------------------------------------
# Utility
# --------------------------------------------------------------------------
def make_dword(ea):
    ida_bytes.del_items(ea, 4, ida_bytes.DELIT_EXPAND)
    ida_bytes.create_data(ea, FF_DWORD, 4, BADADDR)


def make_addr(ea):
    sz = ADDR_SZ
    flag = FF_QWORD if sz == 8 else FF_DWORD
    ida_bytes.del_items(ea, sz, ida_bytes.DELIT_EXPAND)
    ida_bytes.create_data(ea, flag | FF_DATA, sz, BADADDR)
    if read_addr(ea) != 0:
        idc.op_plain_offset(ea, 0, 0)


def is_in_text_segment(addr):
    """Check if an address belongs to an executable code segment."""
    if addr == 0:
        return False
    seg = ida_segment.getseg(addr)
    if seg is None:
        return False
    seg_name = idc.get_segm_name(addr)
    if seg_name in (".text", "__text", "CODE", ".code"):
        return True
    # seg.perm uses SFL_* bits: 1=exec, 2=write, 4=read
    return (seg.perm & 1) != 0 and (seg.perm & 2) == 0


def is_in_data_segment(addr):
    """Check if an address belongs to a data segment (.rdata, .data, etc.)."""
    if addr == 0:
        return False
    seg = ida_segment.getseg(addr)
    if seg is None:
        return False
    seg_name = idc.get_segm_name(addr)
    if seg_name in (".rdata", ".data", "__const", "__data", "DATA", ".rodata"):
        return True
    # Fallback: readable, not executable
    return (seg.perm & 4) != 0 and (seg.perm & 1) == 0


def try_read_revision(data_ptr):
    """Try to read the revision field from a potential data pointer."""
    if data_ptr == 0 or not is_in_data_segment(data_ptr):
        return -1
    rev = read_dword(data_ptr)
    if 7 <= rev <= 20:
        return rev
    return -1


# --------------------------------------------------------------------------
# QMetaObject::Data  (the 'd' struct inside QMetaObject)
#
# With QT_NO_DATA_RELOCATION, SuperData has TWO pointer fields:
#   struct SuperData {
#       const QMetaObject *direct;   // usually NULL
#       Getter indirect;             // function pointer returning parent metaobject
#   };
# making the whole struct one pointer wider.
# --------------------------------------------------------------------------
class QMetaObject_d:
    def __init__(self, offset):
        self.offset = offset
        self.no_data_relocation = False

        # Read the first few pointer-sized values to detect the layout
        ptrs = [read_addr(offset + i * ADDR_SZ) for i in range(9)]

        # ---- Detect QT_NO_DATA_RELOCATION ----
        # Normal layout:     [superdata, stringdata(.rdata),  data(.rdata),  metacall(.text), ...]
        # NoDataReloc layout: [direct,    indirect(.text),    stringdata(.rdata), data(.rdata), metacall(.text), ...]
        #
        # Key heuristic: in normal layout, ptrs[1] is stringdata (in .rdata);
        #                in NoDataReloc,  ptrs[1] is the indirect getter (in .text).
        if is_in_text_segment(ptrs[1]):
            self.no_data_relocation = True

        if self.no_data_relocation:
            # SuperData = { direct, indirect } → 2 pointers
            self.superdata_direct   = ptrs[0]
            self.superdata_indirect = ptrs[1]
            self.superdata = ptrs[0] if ptrs[0] else ptrs[1]
            self.stringdata         = ptrs[2]
            self.data               = ptrs[3]
            self.metacall           = ptrs[4]
            self.relatedMetaObjects = ptrs[5]
            field_idx = 6
        else:
            # SuperData = { direct } → 1 pointer
            self.superdata_direct   = ptrs[0]
            self.superdata_indirect = 0
            self.superdata = ptrs[0]
            self.stringdata         = ptrs[1]
            self.data               = ptrs[2]
            self.metacall           = ptrs[3]
            self.relatedMetaObjects = ptrs[4]
            field_idx = 5

        # Detect Qt6 (has metaTypes field) vs Qt5 by peeking at revision
        rev = try_read_revision(self.data)
        self.is_qt6 = rev >= 9

        if self.is_qt6:
            self.metaTypes = ptrs[field_idx];     field_idx += 1
            self.extradata = ptrs[field_idx];     field_idx += 1
        else:
            self.metaTypes = 0
            self.extradata = ptrs[field_idx];     field_idx += 1

        self.total_fields = field_idx
        self.total_size = field_idx * ADDR_SZ

        self._annotate()

    def _annotate(self):
        ea = self.offset
        for i in range(self.total_fields):
            make_addr(ea + i * ADDR_SZ)

        if self.no_data_relocation:
            labels = ["superdata.direct", "superdata.indirect(getter)"]
        else:
            labels = ["superdata"]

        labels += ["stringdata", "data", "static_metacall", "relatedMetaObjects"]

        if self.is_qt6:
            labels += ["metaTypes", "extradata"]
        else:
            labels += ["extradata"]

        for i, name in enumerate(labels):
            idc.set_cmt(ea + i * ADDR_SZ, name, 0)


# --------------------------------------------------------------------------
# QMetaObjectPrivate  (header of the 'data' uint array)
# Same layout in Qt5 and Qt6, 14 ints
# --------------------------------------------------------------------------
class QMetaObjectPrivate:
    FIELD_COUNT = 14

    def __init__(self, data_ea):
        self.offset = data_ea
        ea = data_ea
        self.revision         = read_dword(ea); ea += 4
        self.className        = read_dword(ea); ea += 4
        self.classInfoCount   = read_dword(ea); ea += 4
        self.classInfoData    = read_dword(ea); ea += 4
        self.methodCount      = read_dword(ea); ea += 4
        self.methodData       = read_dword(ea); ea += 4
        self.propertyCount    = read_dword(ea); ea += 4
        self.propertyData     = read_dword(ea); ea += 4
        self.enumeratorCount  = read_dword(ea); ea += 4
        self.enumeratorData   = read_dword(ea); ea += 4
        self.constructorCount = read_dword(ea); ea += 4
        self.constructorData  = read_dword(ea); ea += 4
        self.flags            = read_dword(ea); ea += 4
        self.signalCount      = read_dword(ea); ea += 4

        for i in range(self.FIELD_COUNT):
            make_dword(data_ea + i * 4)

    @property
    def is_qt6(self):
        return self.revision >= 9

    @property
    def ints_per_method(self):
        return 6 if self.revision >= 9 else 5


# --------------------------------------------------------------------------
# String data parsers
# --------------------------------------------------------------------------
class Qt6StringData:
    """
    Qt6 string data: stringdata is a uint* array.
    For string at index i:
      offset = stringdata[2*i]       (byte offset from start of stringdata)
      length = stringdata[2*i + 1]   (string length, not including null)
      chars  = (const char*)stringdata + offset
    See: qmetaobject.cpp → stringDataView()
    """
    def __init__(self, stringdata_ea):
        self.base_ea = stringdata_ea

    def __getitem__(self, index):
        off_ea = self.base_ea + 8 * index
        offset = read_dword(off_ea)
        length = read_dword(off_ea + 4)
        str_ea = self.base_ea + offset
        result = ida_bytes.get_bytes(str_ea, length)
        if result:
            return result.decode('utf-8', errors='replace')
        return ""

    def annotate_entry(self, index):
        off_ea = self.base_ea + 8 * index
        make_dword(off_ea)
        make_dword(off_ea + 4)
        s = self[index]
        idc.set_cmt(off_ea, f'str[{index}] = "{s}"', 0)


class Qt5StringData:
    """
    Qt5 string data: stringdata is a QByteArrayData* array.
    Each QByteArrayData: { ref(4), size(4), alloc_cap(4), offset(4/8) }
    64-bit entry size = 24, 32-bit = 16.
    String is at: &entry + entry.offset
    Sentinel: ref == 0xFFFFFFFF and alloc == 0.
    """
    ENTRY_SIZE = 24 if ADDR_SZ == 8 else 16

    def __init__(self, stringdata_ea):
        self.base_ea = stringdata_ea
        self._cache = {}
        self._parse()

    def _parse(self):
        ea = self.base_ea
        idx = 0
        while True:
            ref_val = read_dword(ea)
            if ref_val != 0xFFFFFFFF:
                break
            alloc_cap = read_dword(ea + 8)
            if alloc_cap != 0:
                break

            size = read_dword(ea + 4)
            if ADDR_SZ == 8:
                offset_val = idc.get_qword(ea + 16)
            else:
                offset_val = read_dword(ea + 12)

            str_ea = ea + offset_val
            raw = ida_bytes.get_bytes(str_ea, size)
            s = raw.decode('utf-8', errors='replace') if raw else ""
            self._cache[idx] = s
            idx += 1
            ea += self.ENTRY_SIZE

        self.count = idx

    def __getitem__(self, index):
        return self._cache.get(index, "")


# --------------------------------------------------------------------------
# Method flags decoder
# --------------------------------------------------------------------------
def decode_method_flags(flags):
    method_type = flags & 0x0c
    access = flags & 0x03
    type_str = METHOD_TYPE_DICT.get(method_type, "UNKNOWN")
    access_str = METHOD_ACCESS_DICT.get(access, "?")
    result = f"{type_str} {access_str}"
    if flags & 0x10:
        result += " Compat"
    if flags & 0x20:
        result += " Cloned"
    if flags & 0x40:
        result += " Scriptable"
    if flags & 0x80:
        result += " Revisioned"
    if flags & 0x100:
        result += " const"
    return result


def resolve_type(type_info, str_data):
    """Resolve a type info uint to a human-readable type name."""
    if type_info in QMETATYPE_MAP:
        return QMETATYPE_MAP[type_info]
    if type_info & IS_UNRESOLVED_TYPE:
        name_idx = type_info & TYPE_NAME_INDEX_MASK
        return str_data[name_idx]
    return f"type({type_info})"


# --------------------------------------------------------------------------
# Method parser
# --------------------------------------------------------------------------
class ParsedMethod:
    def __init__(self, index, name, ret_type, params, flags_str, ea):
        self.index = index
        self.name = name
        self.ret_type = ret_type
        self.params = params
        self.flags_str = flags_str
        self.ea = ea

    @property
    def signature(self):
        param_strs = [f"{t} {n}" for t, n in self.params]
        return f"{self.flags_str} {self.ret_type} {self.name}({', '.join(param_strs)})"

    def __repr__(self):
        return self.signature


def parse_methods(priv, data_ea, str_data, ints_per_method):
    """Parse all methods from the data[] array."""
    methods = []
    base = data_ea + priv.methodData * 4

    for i in range(priv.methodCount):
        ea = base + i * ints_per_method * 4

        name_idx      = read_dword(ea + 0)
        argc          = read_dword(ea + 4)
        params_offset = read_dword(ea + 8)
        tag_idx       = read_dword(ea + 12)
        flags         = read_dword(ea + 16)

        for j in range(ints_per_method):
            make_dword(ea + j * 4)

        method_name = str_data[name_idx]
        flags_str = decode_method_flags(flags)

        # Parse return type
        ret_type_ea = data_ea + params_offset * 4
        make_dword(ret_type_ea)
        ret_type_info = read_dword(ret_type_ea)
        ret_type = resolve_type(ret_type_info, str_data)
        idc.set_cmt(ret_type_ea, f"ret: {ret_type}", 0)

        # Parse parameter types and names
        params = []
        for p in range(argc):
            ptype_ea = ret_type_ea + (1 + p) * 4
            make_dword(ptype_ea)
            ptype_info = read_dword(ptype_ea)
            ptype = resolve_type(ptype_info, str_data)
            idc.set_cmt(ptype_ea, f"param{p} type: {ptype}", 0)

            pname_ea = ret_type_ea + (1 + argc + p) * 4
            make_dword(pname_ea)
            pname_idx = read_dword(pname_ea)
            pname = str_data[pname_idx]
            idc.set_cmt(pname_ea, f"param{p} name: {pname}", 0)

            params.append((ptype, pname))

        m = ParsedMethod(i, method_name, ret_type, params, flags_str, ea)
        idc.set_cmt(ea, m.signature, 0)
        methods.append(m)

    return methods


# --------------------------------------------------------------------------
# Main parser
# --------------------------------------------------------------------------
class QtMetaParser:
    def __init__(self, d_offset, rename=False):
        self.d_offset = d_offset

        # 1. Parse QMetaObject::Data (auto-detects QT_NO_DATA_RELOCATION)
        self.d = QMetaObject_d(d_offset)

        reloc_tag = " [QT_NO_DATA_RELOCATION]" if self.d.no_data_relocation else ""
        print(f"[QtMetaParser] Layout: {self.d.total_fields} fields, "
              f"{self.d.total_size} bytes{reloc_tag}")

        # 2. Parse QMetaObjectPrivate header
        self.priv = QMetaObjectPrivate(self.d.data)

        qt_ver = "Qt6" if self.priv.is_qt6 else "Qt5"
        print(f"[QtMetaParser] Detected {qt_ver} (revision={self.priv.revision})")

        # 3. Build string data accessor
        if self.priv.is_qt6:
            self.str_data = Qt6StringData(self.d.stringdata)
        else:
            self.str_data = Qt5StringData(self.d.stringdata)

        # 4. Get class name
        self.class_name = self.str_data[self.priv.className]
        print(f"[QtMetaParser] Class: {self.class_name}")

        # Annotate QMetaObjectPrivate header
        hdr_cmmt = (f"CLASS: {self.class_name} [{qt_ver} rev{self.priv.revision}]\n"
                     f"Methods: {self.priv.methodCount}  Signals: {self.priv.signalCount}\n"
                     f"Properties: {self.priv.propertyCount}  Enums: {self.priv.enumeratorCount}\n"
                     f"Constructors: {self.priv.constructorCount}")
        idc.set_cmt(self.d.data, hdr_cmmt, 0)

        # 5. Rename symbols
        if rename:
            self._rename_symbols()

        # 6. Parse methods
        self.methods = parse_methods(
            self.priv, self.d.data, self.str_data, self.priv.ints_per_method
        )

    def _rename_symbols(self):
        cn = self.class_name
        idc.set_name(self.d_offset, f"{cn}::staticMetaObject", ida_name.SN_CHECK)
        idc.set_name(self.d.stringdata, f"qt_meta_stringdata_{cn}", ida_name.SN_CHECK)
        idc.set_name(self.d.data, f"qt_meta_data_{cn}", ida_name.SN_CHECK)

        metacall_name = idc.get_name(self.d.metacall, ida_name.GN_VISIBLE)
        if metacall_name and not metacall_name.startswith("nullsub"):
            idc.set_name(self.d.metacall, f"{cn}::qt_static_metacall", ida_name.SN_CHECK)

        if self.d.no_data_relocation and self.d.superdata_indirect:
            getter_name = idc.get_name(self.d.superdata_indirect, ida_name.GN_VISIBLE)
            if getter_name and getter_name.startswith("sub_"):
                idc.set_name(self.d.superdata_indirect,
                             f"{cn}::superdata_getter", ida_name.SN_CHECK)


# --------------------------------------------------------------------------
# Entry point / display
# --------------------------------------------------------------------------
def displayMetaData(data_addr, rename=False):
    parser = QtMetaParser(data_addr, rename)
    print(f"\n{'='*60}")
    print(f"  {parser.class_name}  (revision {parser.priv.revision})")
    if parser.d.no_data_relocation:
        print(f"  [QT_NO_DATA_RELOCATION mode]")
    print(f"  Methods: {parser.priv.methodCount}  Signals: {parser.priv.signalCount}")
    print(f"{'='*60}")

    for i, m in enumerate(parser.methods):
        tag = ""
        if i < parser.priv.signalCount:
            tag = " [SIGNAL]"
        elif m.flags_str.find("SLOT") >= 0:
            tag = " [SLOT]"
        print(f"  [case {i}] {m.signature}{tag}")

    print(f"{'='*60}\n")
    return parser.methods


# --------------------------------------------------------------------------
# IDA Plugin interface
# --------------------------------------------------------------------------
class QtMetaParserPluginmod(ida_idaapi.plugmod_t):
    def __init__(self):
        super().__init__()
        self._rename = None

    def run(self, arg):
        if self._rename is None:
            self._rename = ida_kernwin.ask_yn(1, "Rename symbols based on metadata?")
            if self._rename == -1:
                return

        ea = idc.get_screen_ea()
        if ea != 0 and ea != BADADDR:
            displayMetaData(ea, bool(self._rename))
        else:
            print("[QtMetaParser] Invalid cursor address.")


class QtMetaParserPlugin(idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL | ida_idaapi.PLUGIN_MULTI
    wanted_name = "QtMetaParser"
    wanted_hotkey = "Alt+;"
    comment = "Parse Qt5/Qt6 MetaObject data structures"
    help = "Place cursor on QMetaObject::Data, then run."

    def init(self):
        idaapi.msg("[QtMetaParser] Plugin loaded. Use Alt+; to parse.\n")
        return QtMetaParserPluginmod()


def PLUGIN_ENTRY():
    return QtMetaParserPlugin()
