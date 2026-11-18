"""把品牌图应用到 Android / Windows / 应用内。

输入：`assets/logo-source.png`（1024×1024，圆角底 + 白色图形）
产出：
  - android .../res/mipmap-*/ic_launcher.png        （传统图标，实心底）
  - android .../res/mipmap-anydpi-v26/ic_launcher*.xml + 前景层
  - android .../res/values/ic_launcher_background.xml
  - windows/runner/resources/app_icon.ico           （多尺寸）
  - app/assets/logo.png                             （应用内品牌图）
"""

from pathlib import Path

from PIL import Image, ImageChops, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "assets" / "logo-source.png"
APP = ROOT / "app"
ANDROID_RES = APP / "android" / "app" / "src" / "main" / "res"
WIN_ICO = APP / "windows" / "runner" / "resources" / "app_icon.ico"
ASSET_LOGO = APP / "assets" / "logo.png"

logo = Image.open(SRC).convert("RGBA")
size = logo.size
print("source", size)

# 1) 背景色：取图形的内侧留白处（避开中心图形与边缘高光）
bg = logo.getpixel((70, 70))
while bg[3] == 0:
    bg = logo.getpixel((70, 70))
print("bg sample", bg)


def smoothstep(x: float, lo: float, hi: float) -> float:
    t = max(0.0, min(1.0, (x - lo) / (hi - lo)))
    return t * t * (3 - 2 * t)


# 2) 从原图里抠出白色图形（按亮度做平滑 alpha，保留抗锯齿）。
#    原图圆角之外是白底，直接按亮度抠会把四个角的白边一起带上，
#    所以先裁掉四周 10% 再取图形。
mx = int(size[0] * 0.10)
my = int(size[1] * 0.10)
core = logo.crop((mx, my, size[0] - mx, size[1] - my))
cpx = core.load()
glyph = Image.new("RGBA", core.size, (255, 255, 255, 0))
gp = glyph.load()
for y in range(core.size[1]):
    for x in range(core.size[0]):
        r, g, b, _a = cpx[x, y]
        lum = 0.2126 * r + 0.7152 * g + 0.0722 * b
        alpha = int(round(255 * smoothstep(lum, 140, 215)))
        if alpha:
            gp[x, y] = (255, 255, 255, alpha)


def fit_glyph(canvas: int, ratio: float) -> Image.Image:
    """把图形按比例放进方形画布中央（透明底）。"""
    bbox = glyph.getbbox()
    if bbox is None:
        raise SystemExit("glyph extraction failed")
    crop = glyph.crop(bbox)
    target = int(canvas * ratio)
    scale = min(target / crop.width, target / crop.height)
    new = crop.resize(
        (max(1, int(crop.width * scale)), max(1, int(crop.height * scale))),
        Image.LANCZOS,
    )
    out = Image.new("RGBA", (canvas, canvas), (0, 0, 0, 0))
    out.paste(new, ((canvas - new.width) // 2, (canvas - new.height) // 2), new)
    return out


def solid_icon(canvas: int, ratio: float) -> Image.Image:
    canvas_img = Image.new("RGBA", (canvas, canvas), bg)
    canvas_img.alpha_composite(fit_glyph(canvas, ratio))
    return canvas_img


# 3) Android 传统图标（实心底，交给启动器裁形）
legacy = {"mdpi": 48, "hdpi": 72, "xhdpi": 96, "xxhdpi": 144, "xxxhdpi": 192}
for bucket, px_size in legacy.items():
    out = solid_icon(px_size, 0.62)
    dst = ANDROID_RES / f"mipmap-{bucket}" / "ic_launcher.png"
    dst.parent.mkdir(parents=True, exist_ok=True)
    out.save(dst)
    print("legacy", dst.name, bucket, px_size)

# 4) Android 自适应图标：432×432 前景（图形占安全区 66%），背景纯色
fg = fit_glyph(432, 0.54)  # 108dp 画布上图形约 58dp，仍在 66dp 安全区内
for bucket in ("mdpi", "hdpi", "xhdpi", "xxhdpi", "xxxhdpi"):
    scale = {"mdpi": 108, "hdpi": 162, "xhdpi": 216, "xxhdpi": 324, "xxxhdpi": 432}[bucket]
    dst = ANDROID_RES / f"mipmap-{bucket}" / "ic_launcher_foreground.png"
    fg.resize((scale, scale), Image.LANCZOS).save(dst)
    print("fg", dst.name, scale)

anydpi = ANDROID_RES / "mipmap-anydpi-v26"
anydpi.mkdir(parents=True, exist_ok=True)
xml = """<?xml version="1.0" encoding="utf-8"?>
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
    <background android:drawable="@color/ic_launcher_background" />
    <foreground android:drawable="@mipmap/ic_launcher_foreground" />
</adaptive-icon>
"""
(anydpi / "ic_launcher.xml").write_text(xml, encoding="utf-8")
(anydpi / "ic_launcher_round.xml").write_text(xml, encoding="utf-8")

color_hex = "#{:02X}{:02X}{:02X}".format(bg[0], bg[1], bg[2])
values = ANDROID_RES / "values"
values.mkdir(parents=True, exist_ok=True)
(values / "ic_launcher_background.xml").write_text(
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<resources>\n'
    f'    <color name="ic_launcher_background">{color_hex}</color>\n'
    "</resources>\n",
    encoding="utf-8",
)
print("bg color", color_hex)

# 5) Windows ico：直接用整张圆角图标，多尺寸
WIN_ICO.parent.mkdir(parents=True, exist_ok=True)
logo.resize((256, 256), Image.LANCZOS).save(
    WIN_ICO,
    format="ICO",
    sizes=[(16, 16), (24, 24), (32, 32), (40, 40), (48, 48), (64, 64), (96, 96), (128, 128), (256, 256)],
)
print("ico", WIN_ICO, WIN_ICO.stat().st_size)

# 6) 应用内品牌图
ASSET_LOGO.parent.mkdir(parents=True, exist_ok=True)
logo.resize((512, 512), Image.LANCZOS).save(ASSET_LOGO)
print("asset", ASSET_LOGO, ASSET_LOGO.stat().st_size)
