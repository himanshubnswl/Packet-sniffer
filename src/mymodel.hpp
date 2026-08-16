#pragma once
#include <QAbstractTableModel>
#include <QVariant>
#include <_bsd_types.h>

struct packet_info {
    u_int64 packet_number;
    QString mac_src;
    QString mac_dest;
    QString int_type;
    QString protocol;
    QString ip4_src;
    QString ip4_dest;
    QString additional_info;
    QString timestamp;
};

class MyModel final : public QAbstractTableModel {
    Q_OBJECT
    std::vector<packet_info> data_array;
    signals:
         void newpacketready(const packet_info& newpacket);
public:
    explicit MyModel(QObject* parent = nullptr);

    [[nodiscard]] int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    [[nodiscard]] int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    [[nodiscard]] QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    [[nodiscard]] QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

    static packet_info give_example();
    void add_packet(const packet_info& packet);

};