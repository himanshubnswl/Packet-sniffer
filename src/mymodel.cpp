//
// Created by lhbdawn on 06-08-2026.
//

#include "mymodel.hpp"

MyModel::MyModel(QObject* parent) : QAbstractTableModel(parent) {
    connect(this, &MyModel::newpacketready, this, &MyModel::add_packet);
}

int MyModel::rowCount(const QModelIndex &parent) const{
    return data_array.size();
}

int MyModel::columnCount(const QModelIndex &parent) const {
    return 6;
}

packet_info MyModel::give_example() {
    packet_info test;
    test.mac_src = QString{"00:1A:2B:3C:4D:5E"};
    test.mac_dest = QString{"AA:BB:CC:DD:EE:FF"};
    test.int_type = QString{"IPV4"};
    test.protocol = QString{"TCP"};
    test.ip4_src = QString{"192.168.1.50"};
    test.ip4_dest = QString{"192.168.1.60"};

    return test;
}

QVariant MyModel::data(const QModelIndex &index, int role) const {
    if (role == Qt::DisplayRole) {
        const auto& packet = data_array[index.row()];

        switch (index.column()) {
            case 0:
                return packet.mac_src;
            case 1:
                return packet.mac_dest;
            case 2:
                return packet.int_type;
            case 3:
                return packet.protocol;
            case 4:
                return packet.ip4_src;
            case 5:
                return packet.ip4_dest;
            default:
                break;
        }
    }
    return {};
}

void MyModel::add_packet(const packet_info& packet) {
    int newindex = data_array.size();

    beginInsertRows(QModelIndex(), newindex, newindex);

    // data_array.push_back(packet);
    data_array.insert(data_array.begin(), packet);

    endInsertRows();
}

QVariant MyModel::headerData(int section, Qt::Orientation orientation, int role) const{
    if (role == Qt::DisplayRole) {
        switch (section) {
            case 0: return "mac src";
            case 1: return "mac dest";
            case 2: return "internet type";
            case 3: return "protocol";
            case 4: return "ipv4 source";
            case 5: return "ipv4 dest";
            default: break;
        }
    }
    return {};
}
