// Render client/icons/riff-logo.svg into the PNG/ICO files Riff uses.
// usage: mkicons <svg> <outdir>
//   outdir/logo.png (200px, About dialog), about.png (48px, window/menu),
//   logo.ico (16..256 px, PNG-compressed entries), preview-<n>.png
#include <QBuffer>
#include <QFile>
#include <QGuiApplication>
#include <QImage>
#include <QPainter>
#include <QSvgRenderer>
#include <QtEndian>
#include <cstdio>

static QImage render(QSvgRenderer &r, int size)
{
    QImage img(size, size, QImage::Format_ARGB32_Premultiplied);
    img.fill(Qt::transparent);
    QPainter p(&img);
    p.setRenderHint(QPainter::Antialiasing);
    p.setRenderHint(QPainter::SmoothPixmapTransform);
    r.render(&p);
    return img;
}

static QByteArray png(const QImage &img)
{
    QByteArray b;
    QBuffer buf(&b);
    buf.open(QIODevice::WriteOnly);
    img.save(&buf, "PNG");
    return b;
}

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);
    if (argc < 3) {
        fprintf(stderr, "usage: mkicons <svg> <outdir>\n");
        return 2;
    }
    QSvgRenderer r(QString::fromLocal8Bit(argv[1]));
    if (!r.isValid()) {
        fprintf(stderr, "bad svg\n");
        return 1;
    }
    QString out = QString::fromLocal8Bit(argv[2]);

    render(r, 200).save(out + "/logo.png");
    render(r, 48).save(out + "/about.png");

    const int sizes[] = {16, 20, 24, 32, 40, 48, 64, 128, 256};
    const int n = sizeof(sizes) / sizeof(sizes[0]);
    QList<QByteArray> data;
    for (int s : sizes)
        data.append(png(render(r, s)));

    // ICO: ICONDIR + ICONDIRENTRY[n] + PNG blobs (Vista+ accepts PNG entries)
    QByteArray ico;
    auto u16 = [&](quint16 v) { v = qToLittleEndian(v); ico.append((const char*)&v, 2); };
    auto u32 = [&](quint32 v) { v = qToLittleEndian(v); ico.append((const char*)&v, 4); };
    u16(0); u16(1); u16(n);
    quint32 offset = 6 + 16 * n;
    for (int i = 0; i < n; i++) {
        ico.append(char(sizes[i] >= 256 ? 0 : sizes[i]));
        ico.append(char(sizes[i] >= 256 ? 0 : sizes[i]));
        ico.append(char(0)); ico.append(char(0));
        u16(1); u16(32);
        u32(data[i].size()); u32(offset);
        offset += data[i].size();
    }
    for (const QByteArray &d : data)
        ico.append(d);
    QFile f(out + "/logo.ico");
    if (!f.open(QIODevice::WriteOnly))
        return 1;
    f.write(ico);
    printf("wrote logo.png about.png logo.ico (%d sizes)\n", n);
    return 0;
}
