package jcprofiler.args.converters;

import com.beust.jcommander.ParameterException;
import com.beust.jcommander.converters.BaseConverter;

public class IntArrayConverter extends BaseConverter<int[]> {
    public IntArrayConverter(final String optionName) {
        super(optionName);
    }

    @Override
    public int[] convert(String value) {
        try {
            String cleanedInput = value.replaceAll("[\\[\\]\\s]", "");

            // Split the cleaned input string into individual values
            String[] valueStrings = cleanedInput.split(",");

            // Create a new int array to store the converted values
            int[] result = new int[valueStrings.length];

            // Convert each value string to an int and store it in the result array
            for (int i = 0; i < valueStrings.length; i++) {
                result[i] = Integer.parseInt(valueStrings[i]);
            }
            return result;
        } catch (NumberFormatException e) {
            throw new ParameterException(getErrorString(value, "is not a valid int array"), e);
        }
    }
}
