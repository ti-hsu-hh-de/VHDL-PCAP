-------------------------------------------------------
--! @file
--! @brief  read data from a PCAP File and present it to the hardware - !ONLY! Simulation !!!
--! @author Dominik Meyer
--! @email dmeyer@hsu-hh.de
--! @date 2016-11-11
-------------------------------------------------------
library ieee;
use ieee.std_logic_1164.all;
use ieee.std_logic_unsigned.all;
use ieee.numeric_std.all;

library UNISIM;
use UNISIM.vcomponents.all;

LIBRARY std;
USE std.textio.all;

--! read data from a PCAP File and present it to the hardware - !ONLY! Simulation !!!

--!
--! the pcap_reader reads a pcap file from harddisk. It ensures that the file is a PCAP file and
--! presents global file data and packet data to other hardware components.
--!
--! This !ONLY! works in Simulation. The code is !NOT! synthesizeable !
--!
entity pcap_reader is
  generic (
    PCAP_FILE_NAME  : STRING  := "dump.pcap";                  --! the name of the PCAP file to read
    ETH_FCS_AVAIL   : boolean := false                         --! has the Ethernet FCS been captured ?
  );
  port (
    -- Global file Data
    ocLinkLayerType   : out std_logic_vector(31 downto 0);    --! which LinkLayer Protocol has been found in pcap file
    ocVersionMajor    : out std_logic_vector(7 downto 0);     --! Major Version Number of File
    ocVersionMinor    : out std_logic_vector(7 downto 0);     --! Minor Version Number of File
    ocEOF             : out std_logic;                        --! end of pcap file reached

    -- Packet File Data
    ocPacketAvailable : out std_logic;                        --! a Packet is available for reading
    ocPacketLength    : out std_logic_vector(31 downto 0);    --! the size of the next Frame in bytes
    ocPacketTimeStamp : out std_logic_vector(31 downto 0);    --! the TimeStamp of the packet in Unix Epoch
    ocMicroSecond     : out std_logic_vector(31 downto 0);    --! the Microsecond in which the packet was captured

    odData            :  out  std_logic_vector(7 downto 0);   --! the next byte of the packet
    ocValid           :  out  std_logic;                      --! indicates if odData is valid
    icReadEnable      :   in  std_logic;                      --! notify that the byte has been read

    iReset          :   in  std_logic;                        --! system clock synchronous reset
    iClk            :   in  std_logic                         --! system clock
    );
end pcap_reader;



--! architecture of the pcap_reader

architecture arch of pcap_reader is

  type t_char_file is FILE of character;
  TYPE t_byte_array is ARRAY (natural RANGE <>) OF std_logic_vector(7 DOWNTO 0);

  FILE PCAP: t_char_file OPEN read_mode IS PCAP_FILE_NAME;

  --
  -- Global Header Signals
  --
  signal srFileID           :  std_logic_vector(31 downto 0);
  signal srMajorVersion     :  std_logic_vector(15 downto 0);
  signal srMinorVersion     :  std_logic_vector(15 downto 0);
  signal scLittleEndian     :  std_logic;
  signal srTimeZoneOffset   :  std_logic_vector(31 downto 0);
  signal srAccuracy         :  std_logic_vector(31 downto 0);
  signal srSnapshotLength   :  std_logic_vector(31 downto 0); --! maximum length of a captured packet
  signal srLinkLayerType    :  std_logic_vector(31 downto 0); --! the type of the lowest layer, e.g. Ethernet, USB

  --
  -- Packet Header Signals
  --
  signal srPacketTimestamp  : std_logic_vector(31 downto 0);  --! UNIX Epoch
  signal srMicroSecond      : std_logic_vector(31 downto 0);
  signal srPacketSize       : std_logic_vector(31 downto 0);  --! size of packet in bytes as it was captured
  signal srPacketSizeWire   : std_logic_vector(31 downto 0);  --! size of packet in bytes as it was seen on the wire

  --
  -- all read signals converted to big endian if necessary
  --
  signal sdMajorVersion     :  std_logic_vector(15 downto 0);
  signal sdMinorVersion     :  std_logic_vector(15 downto 0);
  signal sdTimeZoneOffset   :  std_logic_vector(31 downto 0);
  signal sdAccuracy         :  std_logic_vector(31 downto 0);
  signal sdSnapshotLength   :  std_logic_vector(31 downto 0);
  signal sdLinkLayerType    :  std_logic_vector(31 downto 0);
  signal sdPacketTimestamp  : std_logic_vector(31 downto 0);
  signal sdMicroSecond      : std_logic_vector(31 downto 0);
  signal sdPacketSize       : std_logic_vector(31 downto 0);
  signal sdPacketSizeWire   : std_logic_vector(31 downto 0);
  signal srByteCounter      : integer;
  signal sdByte             : std_logic_vector(7 downto 0);

  type states is (st_start, st_check_file, st_read_global_header, st_read_packet_header, st_packet_available, st_read_packet, st_eof);
  signal current_state : states;

begin

  --
  -- Output signals
  --
  ocLinkLayerType       <= sdLinkLayerType;
  ocVersionMajor        <= sdMajorVersion(7 downto 0);
  ocVersionMinor        <= sdMinorVersion(7 downto 0);
  ocPacketLength        <= sdPacketSize;
  ocPacketTimeStamp     <= sdPacketTimestamp;
  ocMicroSecond         <= sdMicroSecond;
  odData                <= sdByte;


  scLittleEndian        <= '1' when srFileID = x"d4c3b2a1" else '0';

  -- convert read values to BigEndian if required
  sdMajorVersion        <= srMajorVersion(7 downto 0) & srMajorVersion(15 downto 8) when scLittleEndian='1' else srMajorVersion;
  sdMinorVersion        <= srMinorVersion(7 downto 0) & srMinorVersion(15 downto 8) when scLittleEndian='1' else srMinorVersion;
  sdTimeZoneOffset      <= srTimeZoneOffset(7 downto 0) & srTimeZoneOffset(15 downto 8) & srTimeZoneOffset(23 downto 16) & srTimeZoneOffset(31 downto 24) when scLittleEndian='1' else srTimeZoneOffset;
  sdAccuracy            <= srAccuracy(7 downto 0) & srAccuracy(15 downto 8) & srAccuracy(23 downto 16) & srAccuracy(23 downto 16) when scLittleEndian='1' else srAccuracy;
  sdSnapshotLength      <= srSnapshotLength(7 downto 0) & srSnapshotLength(15 downto 8) & srSnapshotLength(23 downto 16) & srSnapshotLength(31 downto 24) when scLittleEndian='1' else srSnapshotLength;
  sdLinkLayerType       <= srLinkLayerType(7 downto 0) & srLinkLayerType(15 downto 8) & srLinkLayerType(23 downto 16) & srLinkLayerType(31 downto 24) when scLittleEndian='1' else srLinkLayerType;
  sdPacketTimestamp     <= srPacketTimestamp(7 downto 0) & srPacketTimestamp(15 downto 8) & srPacketTimestamp(23 downto 16) & srPacketTimestamp(31 downto 24) when scLittleEndian='1' else srPacketTimestamp;
  sdMicroSecond         <= srMicroSecond(7 downto 0) & srMicroSecond(15 downto 8) & srMicroSecond(23 downto 16) & srMicroSecond(31 downto 24) when scLittleEndian='1' else srMicroSecond;
  sdPacketSize          <= srPacketSize(7 downto 0) & srPacketSize(15 downto 8) & srPacketSize(23 downto 16) & srPacketSize(31 downto 24) when scLittleEndian='1' else srPacketSize;
  sdPacketSizeWire      <= srPacketSizeWire(7 downto 0) & srPacketSizeWire(15 downto 8) & srPacketSizeWire(23 downto 16) & srPacketSizeWire(31 downto 24) when scLittleEndian='1' else srPacketSizeWire;


  --! FSM to read data
  process(iClk)
    VARIABLE char_buffer : character;
    VARIABLE eof         : boolean;
  begin

    if (rising_edge(iClk)) then
      if (iReset = '1') then

        srFileID          <= (others => '0');
        srMajorVersion    <= (others => '0');
        srMinorVersion    <= (others => '0');
        srTimeZoneOffset  <= (others => '0');
        srAccuracy        <= (others => '0');
        srSnapshotLength  <= (others => '0');
        srLinkLayerType   <= (others => '0');
        srPacketTimestamp <= (others => '0');
        srMicroSecond     <= (others => '0');
        srPacketSize      <= (others => '0');
        srByteCounter     <= 0;
        sdByte            <= (others => '0');
        ocPacketAvailable <= '0';
        ocValid           <= '0';
        ocEOF             <= '0';
        current_state <= st_start;


      else

        ocValid             <= '0';
        ocPacketAvailable   <= '0';
        ocEOF             <= '0';

        case current_state is
          when st_start       =>
                                  for i in 3 downto 0 loop
                                    if (not(endfile(PCAP))) then
                                      read(PCAP, char_buffer);
                                      srFileID((i*8)+7 downto i*8 ) <= std_logic_vector(to_unsigned(character'POS(char_buffer), 8));
                                    end if;
                                  end loop;

                                  if (endfile(PCAP)) then
                                    current_state <= st_eof;
                                  else
                                    current_state <= st_check_file;
                                  end if;

          when st_check_file  =>
                                  if (srFileID = x"d4c3b2a1" or srFileID=x"a1b2c3d4") then

                                    current_state <= st_read_global_header;

                                  else

                                    report "Selected file is not a PCAP file" severity failure;

                                  end if;

          when st_read_global_header=>
                              for i in 1 downto 0 loop
                                if (not(endfile(PCAP))) then
                                  read(PCAP, char_buffer);
                                  srMajorVersion((i*8)+7 downto i*8 ) <= std_logic_vector(to_unsigned(character'POS(char_buffer), 8));
                                end if;
                              end loop;

                              for i in 1 downto 0 loop
                                if (not(endfile(PCAP))) then
                                  read(PCAP, char_buffer);
                                  srMinorVersion((i*8)+7 downto i*8 ) <= std_logic_vector(to_unsigned(character'POS(char_buffer), 8));
                                end if;
                              end loop;

                              for i in 3 downto 0 loop
                                if (not(endfile(PCAP))) then
                                  read(PCAP, char_buffer);
                                  srTimeZoneOffset((i*8)+7 downto i*8 ) <= std_logic_vector(to_unsigned(character'POS(char_buffer), 8));
                                end if;
                              end loop;

                              for i in 3 downto 0 loop
                                if (not(endfile(PCAP))) then
                                  read(PCAP, char_buffer);
                                  srAccuracy((i*8)+7 downto i*8 ) <= std_logic_vector(to_unsigned(character'POS(char_buffer), 8));
                                end if;
                              end loop;

                              for i in 3 downto 0 loop
                                if (not(endfile(PCAP))) then
                                  read(PCAP, char_buffer);
                                  srSnapshotLength((i*8)+7 downto i*8 ) <= std_logic_vector(to_unsigned(character'POS(char_buffer), 8));
                                end if;
                              end loop;

                              for i in 3 downto 0 loop
                                if (not(endfile(PCAP))) then
                                  read(PCAP, char_buffer);
                                  srLinkLayerType((i*8)+7 downto i*8 ) <= std_logic_vector(to_unsigned(character'POS(char_buffer), 8));
                                end if;
                              end loop;

                              if (endfile(PCAP)) then
                                current_state <= st_eof;
                              else
                                current_state <= st_read_packet_header;
                              end if;

          when st_read_packet_header  =>

                              for i in 3 downto 0 loop
                                if (not(endfile(PCAP))) then
                                  read(PCAP, char_buffer);
                                  srPacketTimestamp((i*8)+7 downto i*8 ) <= std_logic_vector(to_unsigned(character'POS(char_buffer), 8));
                                end if;
                              end loop;

                              for i in 3 downto 0 loop
                                if (not(endfile(PCAP))) then
                                  read(PCAP, char_buffer);
                                  srMicroSecond((i*8)+7 downto i*8 ) <= std_logic_vector(to_unsigned(character'POS(char_buffer), 8));
                                end if;
                              end loop;

                              for i in 3 downto 0 loop
                                if (not(endfile(PCAP))) then
                                  read(PCAP, char_buffer);
                                  srPacketSize((i*8)+7 downto i*8 ) <= std_logic_vector(to_unsigned(character'POS(char_buffer), 8));
                                end if;
                              end loop;

                              for i in 3 downto 0 loop
                                if (not(endfile(PCAP))) then
                                  read(PCAP, char_buffer);
                                  srPacketSizeWire((i*8)+7 downto i*8 ) <= std_logic_vector(to_unsigned(character'POS(char_buffer), 8));
                                end if;
                              end loop;

                              if (endfile(PCAP)) then
                                current_state <= st_eof;
                              else
                                current_state <= st_packet_available;
                              end if;

          when st_packet_available   =>
                              srByteCounter <= conv_integer(sdPacketSize);
                              if (not(endfile(PCAP))) then
                                read(PCAP, char_buffer);
                                sdByte            <= std_logic_vector(to_unsigned(character'POS(char_buffer), 8));
                                ocValid           <= '1';
                                ocPacketAvailable <= '1';
                                current_state <= st_read_packet;
                              else
                                current_state <= st_eof;
                              end if;


          when st_read_packet        =>
                              ocPacketAvailable   <= '1';
                              ocValid             <= '1';
                              sdByte              <= sdByte;
                              if (srByteCounter > 1 and icReadEnable='1') then
                                srByteCounter   <= srByteCounter -1;
                                if (not(endfile(PCAP))) then
                                  read(PCAP, char_buffer);
                                  sdByte        <= std_logic_vector(to_unsigned(character'POS(char_buffer), 8));
                                  current_state <= st_read_packet;
                                else
                                  current_state <= st_eof;
                                end if;

                              elsif(srByteCounter > 1 and icReadEnable='0') then
                                current_state <= st_read_packet;
                              else
                                ocValid           <= '0';
                                ocPacketAvailable <= '0';
                                current_state <= st_read_packet_header;
                              end if;

          when st_eof             =>
                                      ocEOF             <= '1';

                                      current_state     <= st_eof;


        end case;


      end if;

    end if;

  end process;


end arch;
