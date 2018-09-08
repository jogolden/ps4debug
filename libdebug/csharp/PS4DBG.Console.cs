using System.Text;

namespace libdebug
{
    public partial class PS4DBG
    {   
        //console
        // packet sizes
        // send size
        private const int CMD_CONSOLE_PRINT_PACKET_SIZE = 4;
        private const int CMD_CONSOLE_NOTIFY_PACKET_SIZE = 8;


        // console
        // note: the disconnect command actually uses the console api to end the connection
        /// <summary>
        /// Reboot console
        /// </summary>
        public void Reboot()
        {
            CheckConnected();

            SendCMDPacket(CMDS.CMD_CONSOLE_REBOOT, 0);
            IsConnected = false;
        }

        /// <summary>
        /// Print to serial port
        /// </summary>
        public void Print(string str)
        {
            CheckConnected();

            string raw = str + "\0";

            SendCMDPacket(CMDS.CMD_CONSOLE_PRINT, CMD_CONSOLE_PRINT_PACKET_SIZE, raw.Length);
            SendData(Encoding.ASCII.GetBytes(raw), raw.Length);
            CheckStatus();
        }

        /// <summary>
        /// Notify console
        /// </summary>
        public void Notify(int messageType, string message)
        {
            CheckConnected();

            string raw = message + "\0";

            SendCMDPacket(CMDS.CMD_CONSOLE_NOTIFY, CMD_CONSOLE_NOTIFY_PACKET_SIZE, messageType, raw.Length);
            SendData(Encoding.ASCII.GetBytes(raw), raw.Length);
            CheckStatus();
        }

        /// <summary>
        /// Console information
        /// </summary>
        public void GetConsoleInformation()
        {
            CheckConnected();

            SendCMDPacket(CMDS.CMD_CONSOLE_INFO, 0);
            CheckStatus();

            // TODO return the data
        }
    }
}