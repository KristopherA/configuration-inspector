import AppKit
let destination = CommandLine.arguments[1]
try FileManager.default.createDirectory(atPath: destination, withIntermediateDirectories: true)
for size in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let pixels = size * scale
        let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels, bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)
        let factor = CGFloat(pixels) / 1024
        let transform = NSAffineTransform(); transform.scale(by: factor); transform.concat()
        NSColor(calibratedRed: 0.22, green: 0.26, blue: 0.58, alpha: 1).setFill()
        NSBezierPath(roundedRect: NSRect(x: 40, y: 40, width: 944, height: 944), xRadius: 210, yRadius: 210).fill()
        NSColor.white.withAlphaComponent(0.85).setStroke()
        let lines = NSBezierPath(); lines.lineWidth = 30
        for y in [CGFloat(330), CGFloat(510), CGFloat(690)] { lines.move(to: NSPoint(x: 240,y:y)); lines.line(to: NSPoint(x: 784,y:y)) }
        lines.stroke()
        NSColor(calibratedRed:0.65,green:0.85,blue:1,alpha:1).setFill()
        for (x,y) in [(CGFloat(400),CGFloat(690)),(CGFloat(650),CGFloat(510)),(CGFloat(470),CGFloat(330))] {
            NSBezierPath(roundedRect:NSRect(x:x-38,y:y-63,width:76,height:126),xRadius:30,yRadius:30).fill()
        }
        NSGraphicsContext.restoreGraphicsState()
        let name = "icon_\(size)x\(size)" + (scale == 2 ? "@2x" : "") + ".png"
        try bitmap.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: destination).appendingPathComponent(name))
    }
}
// Store PNG icon representations directly in the documented ICNS chunk container.
var chunks = Data()
for (type, name) in [("icp4", "icon_16x16.png"), ("icp5", "icon_32x32.png"), ("icp6", "icon_32x32@2x.png"), ("ic07", "icon_128x128.png"), ("ic08", "icon_256x256.png"), ("ic09", "icon_512x512.png"), ("ic10", "icon_512x512@2x.png")] {
    let png = try Data(contentsOf: URL(fileURLWithPath: destination).appendingPathComponent(name))
    chunks.append(Data(type.utf8))
    var length = UInt32(png.count + 8).bigEndian
    withUnsafeBytes(of: &length) { chunks.append(contentsOf: $0) }
    chunks.append(png)
}
var container = Data("icns".utf8)
var length = UInt32(chunks.count + 8).bigEndian
withUnsafeBytes(of: &length) { container.append(contentsOf: $0) }
container.append(chunks)
try container.write(to: URL(fileURLWithPath: CommandLine.arguments[2]))
