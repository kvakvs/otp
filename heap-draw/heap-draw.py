#!/usr/bin/python3

import copy
import os
import sys

from PIL import Image, ImageDraw, ImageFont

WORDSIZE = 8
# Image color and margins
#
IMG_FILL = (255, 255, 255, 0)
IMG_EXTRA_HEIGHT = 32  # how many pixels extra around zones
INTERVAL_BTW_HEAPS = 32

# Zone box size and color
#
STYLE = dict(
    image=dict(line=None, fill=None, padding=32),
    # zone box, big delimiting box around memory zones
    zbox=dict(padding=4, line=(128, 128, 128, 0), fill=(235, 235, 235, 0)),
    # subzone - inner boxes like stack or heap
    # subzbox=dict(padding=2, line=(128, 128, 128, 0), fill=(220, 220, 220, 0)),
    # zone box, big delimiting box around memory zones
    term=dict(padding=0, line=None, fill=(0, 0, 0, 0)),
    term_mark=dict(padding=0, line=None, fill=(0, 0, 0, 0))
)

BASEDIR, BASEFILENAME = os.path.split(sys.argv[0])
FONT = ImageFont.truetype("%s/coders_crux/coders_crux.ttf" % BASEDIR, 15)


def setup_styles():
    global STYLE
    # Stack will be more red
    # s = copy.copy(STYLE["subzbox"])
    # s["fill"] = (240, 240, 240, 0)
    # STYLE["stack"] = s
    #
    # # Heaps will be more blue
    # s = copy.copy(STYLE["subzbox"])
    # s["fill"] = (240, 240, 240, 0)
    # STYLE["old_hp"] = s


class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def tuple(self):
        return self.x, self.y

    def __repr__(self):
        return "Point(%s,%s)" % self.tuple()

    def grow(self, p):
        if p.x > self.x:
            self.x = p.x
        if p.y > self.y:
            self.y = p.y

    def __mul__(self, n: float):
        return Point(self.x * n, self.y * n)

    def __add__(self, p: 'Point'):
        newp = Point(self.x, self.y)
        newp += p
        return newp

    def __iadd__(self, p):
        self.x += p.x
        self.y += p.y
        return self


class DrawBox:
    # Size can be have x or y or both set to None
    def __init__(self, parent: 'DrawBox', pos: Point, size: Point,
                 style_or_name):
        self.parent = parent
        assert(pos is not None)
        self.pos = copy.copy(pos)
        assert(size is not None)
        self.size = copy.copy(size)

        if isinstance(style_or_name, dict):
            self.style = copy.copy(style_or_name)
        else:
            self.style = STYLE[style_or_name] \
                if style_or_name in STYLE else STYLE['zbox']

        self.children = []
        self.name = ""

    def __repr__(self):
        return "DrawBox(%s, org=%s, sz=%s)" % (self.name, self.pos, self.size)

    def get_padding(self):
        p = self.style.get("padding", 0)
        return Point(p, p)

    def get_size(self):
        padding = self.get_padding()

        # Take a smallest box and grow it to fit all children in
        # +--+ <- padding
        # |  | we begin below, after padding, add all nested blocks, then 2*pad
        # |--+-------+
        # |  |   +---+---+
        # |  +---|---+ <- self.size
        # |      +-------+ <- some content
        size = Point(0, 0)
        size.grow(self.size)

        for c in self.children:
            size.grow(c.get_size() + c.pos)

        size += padding * 2  # add margins for all sides
        return size

    def draw(self, draw: ImageDraw.ImageDraw, org0: Point, draw_gfx: bool):
        padding = self.get_padding()
        pos = org0 + self.pos

        # Separate drawing graphics and text, so that text can be overlayed
        # later and not be erased by other blocks
        if draw_gfx:
            xy1 = pos.tuple()
            xy2 = (pos + self.get_size() + Point(-1, -1)).tuple()
            draw.rectangle([xy1, xy2],
                           self.style.get("fill", None),
                           self.style.get("line", (0, 0, 0, 0)))
        else:
            sz = self.get_size()
            draw.text((pos + Point(sz.x, 0) + Point(0, -9)).tuple(), self.name,
                      font=FONT, fill=(0, 0, 0, 0))

        for c in self.children:
            c.draw(draw, pos + padding, draw_gfx)


class Zone:
    # From string
    def __init__(self, s: str):
        s = s.strip().split(" ")
        # format of line is:
        # ZONEDEF <name> RANGE <hex1> <hex2> PARENT <parent_zone_name>
        assert s[0] == "ZONEDEF" or s[0] == "HEAPDEF"
        self.contains_terms = (s[0] == "HEAPDEF")

        self.name = s[1]
        assert s[2] == "RANGE"
        self.begin = int(s[3], 16)
        self.end = int(s[4], 16)
        assert s[5] == "PARENT"
        self.parent = s[6]

        # Guess visible height
        self.height = (self.end - self.begin) // WORDSIZE

    def __repr__(self):
        return "Zone(%s,[%x..%x])" % (self.name, self.begin, self.end)

    def contains(self, addr):
        return self.begin <= addr <= self.end


class Term:
    def __init__(self, s):
        s = s.strip().split(" ")
        assert(s[0] == "TERM")
        self.addr = int(s[1], 16)
        # flags can be: [B]ox [C]ons [R]oot [M]oved [I]mmed [*]CP
        self.flags = s[2] if len(s) > 2 else ""

    def prepare(self, parent, offs):
        style = copy.copy(STYLE["term"])
        width = 16

        if "B" in self.flags:  # box
            style['fill'] = (192, 128, 128, 0)
        if "*" in self.flags:  # cp
            style['fill'] = (64, 128, 240, 0)
        if "C" in self.flags:  # cons
            style['fill'] = (128, 192, 128, 0)
        if "M" in self.flags:  # moved
            offs = offs + Point(4, 0)

        d = DrawBox(parent, offs, Point(width, 1), style)

        if "R" in self.flags:  # root
            d.children.append(DrawBox(d, Point(width + 2, 0), Point(2, 1),
                                      "term_mark"))
        return d


class HeapDump:
    def __init__(self, f_name):
        self.zones, self.terms = self.read(f_name)

    @staticmethod
    def read(f_name):
        zones = []
        terms = []
        with open(f_name, "rt") as in_f:
            while True:
                ln = in_f.readline()
                if not ln:
                    break
                if ln.startswith("TERM "):
                    terms.append(Term(ln))
                if ln.startswith("ZONEDEF ") or ln.startswith("HEAPDEF "):
                    zones.append(Zone(ln))

        return zones, terms

    def prepare(self):
        root = DrawBox(None, Point(0, 0), Point(32, 32), "image")
        root.name = ""

        org = Point(0, 0)
        for z in self.zones:
            if z.parent != "-":
                continue  # take only top level zones which have no parent
            box = self.prepare_zone(root, org, z)
            root.children.append(box)
            org += Point(box.get_size().x + INTERVAL_BTW_HEAPS, 0)

        return root

    def prepare_zone(self, parent, org, z):
        print("drawing zone %s inside %s org %s" % (z.name, parent.name, org))

        style = STYLE["zbox"]
        if z.name in STYLE:  # style override if exists
            style = STYLE[z.name]

        box = DrawBox(parent, org, Point(style.get('width', 16), z.height),
                      z.name)
        box.name = z.name

        # Terms display
        if z.contains_terms:
            for term in self.terms:
                if z.contains(term.addr):
                    offs = Point(0, (z.end - term.addr) // WORDSIZE)
                    box.children.append(term.prepare(box, offs))

        # Take all zones which have this for parent
        for subz in self.zones:
            if subz.parent != z.name:
                continue  # take only top level zones which have no parent

            offs = Point(0, (z.end - subz.end) // WORDSIZE)
            box.children.append(
                self.prepare_zone(box, offs, subz))

        return box


def main(f_name):
    setup_styles()
    dump = HeapDump(f_name)

    # Build tree of nested boxes
    dom = dump.prepare()

    sz = dom.get_size()
    sz.grow(Point(300, 0))
    img = Image.new('RGB', sz.tuple(), IMG_FILL)
    draw = ImageDraw.Draw(img)

    dom.draw(draw, Point(0, 0), True)  # draw graphics first
    dom.draw(draw, Point(0, 0), False)  # then overlay text

    draw.text((0, 0), "Red: BOX, Green: CONS, Shifted right: Moved",
              font=FONT, fill=(0, 0, 0, 0))
    draw.text((0, 10), "Extra dot: root set",
              font=FONT, fill=(0, 0, 0, 0))

    img.save(f_name + ".png", "PNG")

main(sys.argv[1])
