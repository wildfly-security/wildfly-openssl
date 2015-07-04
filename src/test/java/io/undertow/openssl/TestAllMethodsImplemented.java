package io.undertow.openssl;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A really hacky test that all methods are implemented
 *
 * @author Stuart Douglas
 */
public class TestAllMethodsImplemented {



    @Test
    public void testAllMethodsImplemented() throws IOException {

        Set<String> implemented = new HashSet<>();
        Pattern pattern = Pattern.compile("UT_OPENSSL\\([^,]*,([^\\)]*)");
        File path = new File("libutssl" + File.separator + "src");
        for(String i : path.list()) {
            String file = read(new File(path, i));
            Matcher matcher = pattern.matcher(file);
            while (matcher.find()) {
                implemented.add(matcher.toMatchResult().group(1).trim());
            }
        }
        Set<String> notImplemented = new HashSet<>();
        for(Method m : SSL.class.getDeclaredMethods()) {
            if(Modifier.isNative(m.getModifiers())) {
                if(!implemented.remove(m.getName())) {
                    notImplemented.add(m.getName());
                }
            }
        }
        if(!notImplemented.isEmpty()) {
            throw new RuntimeException("Not implemented " + notImplemented);
        }
        if(!implemented.isEmpty()) {
            throw new RuntimeException("Not needed " + implemented);
        }
    }

    private String read(File file) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[100];
        try (FileInputStream in = new FileInputStream(file)) {
            int r;
            while ((r = in.read(buf)) > 0) {
                out.write(buf, 0, r);
            }
        }
        return new String(out.toByteArray());
    }

}
