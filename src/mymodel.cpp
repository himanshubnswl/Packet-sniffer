//
// Created by lhbdawn on 06-08-2026.
//

#include "mymodel.hpp"
/*The Application needs a custom model to handle the incoming packet data
 * this is because traditional model won't allow and won't be efficient in handling the large amount of incoming
 * packet. the custom model needs to inherit the QAbstractTableModel and override it's functions which then will be
 * used by the view to display it on the screen. this is the model/view architecture that qt follows.
 *
 * hence rowCount, columnCount, data, headerData have been overridden. there are roles for which a function can be called.
 * will be following the data role in all of them. function is quried with a index and a item needs be returned for
 * the given index, QVariant has all kinds of data types.
 */
MyModel::MyModel(QObject* parent) : QAbstractTableModel(parent) {
    data_array.reserve(10000);
    connect(this, &MyModel::newpacketready, this, &MyModel::add_packet);
}

int MyModel::rowCount(const QModelIndex &parent) const{
    return data_array.size();
}

int MyModel::columnCount(const QModelIndex &parent) const {
    return 9;
}

QVariant MyModel::data(const QModelIndex &index, int role) const {
    if (role == Qt::DisplayRole) {
        const auto& packet = data_array[index.row()];

        switch (index.column()) {
            case 0:
                return packet.packet_number;
            case 1:
                return packet.timestamp;
            case 2:
                return packet.mac_src;
            case 3:
                return packet.mac_dest;
            case 4:
                return packet.int_type;
            case 5:
                return packet.protocol;
            case 6:
                return packet.ip_src;
            case 7:
                return packet.ip_dest;
            case 8:
                return packet.additional_info;
            default:
                break;
        }
    }
    return {};
}

void MyModel::add_packet(const packet_info& packet) {
    int newindex = data_array.size();

    beginInsertRows(QModelIndex(), newindex, newindex);

    data_array.push_back(packet);

    endInsertRows();
}

QVariant MyModel::headerData(int section, Qt::Orientation orientation, int role) const{
    if (role == Qt::DisplayRole) {
        switch (section) {
            case 0: return "packet no.";
            case 1: return "timestamp";
            case 2: return "mac src";
            case 3: return "mac dest";
            case 4: return "internet type";
            case 5: return "protocol";
            case 6: return "ipv4 source";
            case 7: return "ipv4 dest";
            case 8: return "additional info";
            default: break;
        }
    }
    return {};

}
packet_info MyModel::give_example() {
    packet_info test;
    test.mac_src = QString{"00:1A:2B:3C:4D:5E"};
    test.mac_dest = QString{"AA:BB:CC:DD:EE:FF"};
    test.int_type = QString{"IPV4"};
    test.protocol = QString{"TCP"};
    test.ip_src = QString{"192.168.1.50"};
    test.ip_dest = QString{"192.168.1.60"};

    return test;
}
