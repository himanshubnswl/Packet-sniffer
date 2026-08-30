#include <QApplication>
#include "window.hpp"
#include "socket.hpp"


//application starts from here, only notable thing here is the jthread, which is needed to not block this thread, so
//it runs in a different thread, and signals the model whenver a new packet has been received
int main(int argc, char **argv) {
    pcap_if_t *alldevs{nullptr};
    auto *device = Socket::selectdev(alldevs);
    QApplication app(argc, argv);
    Window window;
    std::jthread capture_thread([device, &window](std::stop_token stop_token) {
        Socket::printpackets(device, window.model, stop_token);
    });

    pcap_freealldevs(alldevs);
    window.show();
    return app.exec();
}
