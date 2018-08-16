/*
 * Copyright 2014 Samoilenko Yuri <kinnalru@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License or (at your option) version 3 or any later version
 * accepted by the membership of KDE e.V. (or its successor approved
 * by the membership of KDE e.V.), which shall act as a proxy
 * defined in Section 14 of version 3 of the license.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>. 
*/

package org.kde.kdeconnect.Plugins.SftpPlugin;

import android.content.Context;
import android.util.Log;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.file.nativefs.NativeFileSystemFactory;
import org.apache.sshd.common.kex.BuiltinDHFactories;
import org.apache.sshd.server.ServerBuilder;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.kex.DHGEXServer;
import org.apache.sshd.server.kex.DHGServer;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.scp.ScpCommandFactory;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.subsystem.sftp.SftpSubsystemFactory;
import org.kde.kdeconnect.Device;
import org.kde.kdeconnect.Helpers.RandomHelper;
import org.kde.kdeconnect.Helpers.SecurityHelpers.SslHelper;

import java.io.File;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.security.PublicKey;
import java.security.Security;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;

class SimpleSftpServer {
    private static final int STARTPORT = 1739;
    private static final int ENDPORT = 1764;

    static final String USER = "kdeconnect";

    private int port = -1;
    private boolean started = false;

    private final SimplePasswordAuthenticator passwordAuth = new SimplePasswordAuthenticator();
    private final SimplePublicKeyAuthenticator keyAuth = new SimplePublicKeyAuthenticator();

    private SshServer sshd;

    static {
        Security.insertProviderAt(SslHelper.BC, 1);
        //SecurityUtils.setRegisterBouncyCastle(false);
    }
    public void init(Context context, Device device) {

        System.setProperty("user.home", "/"); //Hack
        NativeFileSystemFactory fileSystemFactory = new NativeFileSystemFactory(false);
        fileSystemFactory.setUsersHomeDir("/");

        sshd = ServerBuilder.builder()
            .keyExchangeFactories(Arrays.asList(
                    DHGEXServer.newFactory(BuiltinDHFactories.dhgex),
                    DHGEXServer.newFactory(BuiltinDHFactories.dhgex256),
                    DHGServer.newFactory(BuiltinDHFactories.ecdhp256),
                    DHGServer.newFactory(BuiltinDHFactories.ecdhp384),
                    DHGServer.newFactory(BuiltinDHFactories.ecdhp521)
            ))
            .fileSystemFactory(fileSystemFactory)
            .build();

        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(new File(context.getFilesDir() + "/sftpd.ser")));
        sshd.setCommandFactory(new ScpCommandFactory());
        sshd.setSubsystemFactories(Collections.singletonList(new SftpSubsystemFactory()));

        sshd.setPublickeyAuthenticator(keyAuth);
        sshd.setPasswordAuthenticator(passwordAuth);
    }

    public boolean start() {
        if (!started) {

            passwordAuth.password = RandomHelper.randomString(28);

            port = STARTPORT;
            while (!started) {
                try {
                    sshd.setPort(port);
                    sshd.start();
                    started = true;
                } catch (Exception e) {
                    e.printStackTrace();
                    port++;
                    if (port >= ENDPORT) {
                        port = -1;
                        Log.e("SftpServer", "No more ports available");
                        return false;
                    }
                }
            }
        }

        return true;
    }

    public void stop() {
        try {
            started = false;
            sshd.stop(true);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String getPassword() {
        return passwordAuth.password;
    }

    public int getPort() {
        return port;
    }

    public String getLocalIpAddress() {
        String ip6 = null;
        try {
            for (Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces(); en.hasMoreElements(); ) {
                NetworkInterface intf = en.nextElement();

                // Anything with rmnet is related to cellular connections or USB
                // tethering mechanisms.  See:
                //
                // https://android.googlesource.com/kernel/msm/+/android-msm-flo-3.4-kitkat-mr1/Documentation/usb/gadget_rmnet.txt
                //
                // If we run across an interface that has this, we can safely
                // ignore it.  In fact, it's much safer to do.  If we don't, we
                // might get invalid IP adddresses out of it.
                if (intf.getDisplayName().contains("rmnet")) continue;

                for (Enumeration<InetAddress> enumIpAddr = intf.getInetAddresses(); enumIpAddr.hasMoreElements(); ) {
                    InetAddress inetAddress = enumIpAddr.nextElement();
                    if (!inetAddress.isLoopbackAddress()) {
                        String address = inetAddress.getHostAddress();
                        if (inetAddress instanceof Inet4Address) { //Prefer IPv4 over IPv6, because sshfs doesn't seem to like IPv6
                            return address;
                        } else {
                            ip6 = address;
                        }
                    }
                }
            }
        } catch (SocketException ex) {
        }
        return ip6;
    }
    /*
        static class AndroidFileSystemFactory implements FileSystemFactory {

            final private Context context;

            public AndroidFileSystemFactory(Context context) {
                this.context = context;
            }

            @Override
            public FileSystem createFileSystem(Session session) throws IOException {
                return new AndroidFileSystem(session.getUsername(), context);
            }
        }

        static class AndroidFileSystem extends NativeFileSystem {

            final private String userName;
            final private Context context;

            public AndroidFileSystemView(final String userName, Context context) {
                super(userName, true);
                this.userName = userName;
                this.context = context;
            }

            @Override
            protected SshFile getFile(final String dir, final String file) {
                File fileObj = new File(dir, file);
                return new AndroidSshFile(fileObj, userName, context);
            }
        }

        static class AndroidSshFile extends NativeSshFile {

            final private Context context;
            final private File file;

            public AndroidSshFile(final File file, final String userName, Context context) {
                super(file.getAbsolutePath(), file, userName);
                this.context = context;
                this.file = file;
            }

            @Override
            public OutputStream createOutputStream(long offset) throws IOException {
                if (!isWritable()) {
                    throw new IOException("No write permission : " + file.getName());
                }

                final RandomAccessFile raf = new RandomAccessFile(file, "rw");
                try {
                    if (offset < raf.length()) {
                        throw new IOException("Your SSHFS is bugged"); //SSHFS 3.0 and 3.2 cause data corruption, abort the transfer if this happens
                    }
                    raf.setLength(offset);
                    raf.seek(offset);

                    return new FileOutputStream(raf.getFD()) {
                        public void close() throws IOException {
                            super.close();
                            raf.close();
                        }
                    };
                } catch (IOException e) {
                    raf.close();
                    throw e;
                }
            }

            @Override
            public boolean delete() {
                //Log.e("Sshd", "deleting file");
                boolean ret = super.delete();
                if (ret) {
                    MediaStoreHelper.indexFile(context, Uri.fromFile(file));
                }
                return ret;

            }

            @Override
            public boolean create() throws IOException {
                //Log.e("Sshd", "creating file");
                boolean ret = super.create();
                if (ret) {
                    MediaStoreHelper.indexFile(context, Uri.fromFile(file));
                }
                return ret;

            }
        }
    */
    static class SimplePasswordAuthenticator implements PasswordAuthenticator {

        public String password;

        @Override
        public boolean authenticate(String user, String password, ServerSession session) {
            return user.equals(SimpleSftpServer.USER) && password.equals(this.password);
        }
    }

    static class SimplePublicKeyAuthenticator implements PublickeyAuthenticator {

        public PublicKey deviceKey;

        @Override
        public boolean authenticate(String user, PublicKey key, ServerSession session) {
            return deviceKey.equals(key);
        }

    }

}
