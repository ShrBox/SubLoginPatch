/**
 * @file plugin.cpp
 * @brief The main file of the plugin
 */

#include <llapi/LoggerAPI.h>
#include "version.h"
#include "llapi/mc/SubClientLoginPacket.hpp"
#include "llapi/mc/ReadOnlyBinaryStream.hpp"
// We recommend using the global logger.
extern Logger logger;

/**
 * @brief The entrypoint of the plugin. DO NOT remove or rename this function.
 *        
 */
void PluginInit()
{
    if (ll::getLoaderVersion() == ll::Version(2, 13, 1)) {
        logger.warn("The LiteLoader version you are using have fixed SubClientLogin exploit");
        logger.warn("There is no need to install this plugin, please remove this plugin");
    }
}

// Fix SubClient exploit: Getting OP by using OP's xuid to join server
TInstanceHook(StreamReadResult, "?_read@SubClientLoginPacket@@EEAA?AW4StreamReadResult@@AEAVReadOnlyBinaryStream@@@Z",
              SubClientLoginPacket, class ReadOnlyBinaryStream& binaryStream) {
    size_t readPointer = binaryStream.getReadPointer();
    unsigned int header = binaryStream.getUnsignedInt();
    unsigned int senderSubClientId = (header >> 10) & 3;
    unsigned int targetSubClientId = (header >> 12) & 3;
    binaryStream.setReadPointer(readPointer);
    if (targetSubClientId != 0 || senderSubClientId != 0) {
        return StreamReadResult::Valid;
    }
    return original(this, binaryStream);
}
