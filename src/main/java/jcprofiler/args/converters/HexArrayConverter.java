package jcprofiler.args.converters;

import com.beust.jcommander.ParameterException;
import com.beust.jcommander.converters.BaseConverter;
import cz.muni.fi.crocs.rcard.client.Util;

public class HexArrayConverter extends BaseConverter<byte[][]> {
    public HexArrayConverter(final String optionName) {
        super(optionName);
    }

    @Override
    public byte[][] convert(String value) {
        try {
            String cleanedInput = value.replaceAll("[\\[\\]\\s]", "");

            // Split the cleaned input string into individual values
            String[] valueStrings = cleanedInput.split(",");

            // Create a new int array to store the converted values
            byte[][] result = new byte[valueStrings.length][];

            // Convert each value string to an int and store it in the result array
            for (int i = 0; i < valueStrings.length; i++) {
                if (valueStrings[i].length() % 2 == 1)
                    throw new ParameterException(getErrorString(valueStrings[i], "is not a valid hex string"));
                result[i] = Util.hexStringToByteArray(valueStrings[i]);
            }
            return result;
        } catch (NumberFormatException e) {
            throw new ParameterException(getErrorString(value, "is not a valid array of hex strings"), e);
        }
    }
}
