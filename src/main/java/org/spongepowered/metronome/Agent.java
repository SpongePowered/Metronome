/*
 * This file is part of Metronome, licensed under the MIT License (MIT).
 *
 * Copyright (c) SpongePowered <https://www.spongepowered.org>
 * Copyright (c) contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.spongepowered.metronome;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * Metronome agent
 */
public final class Agent {
    
    /**
     * Class transformer which adds callbacks into LaunchClassLoader
     */
    static class Transformer implements ClassFileTransformer {
        
        static final String CL_CLASSLOADER = "net/minecraft/launchwrapper/LaunchClassLoader";
        static final String CL_LOGWRAPPER = "net/minecraft/launchwrapper/LogWrapper";
        static final String CL_TRANSFORMER = "net/minecraft/launchwrapper/IClassTransformer";
        static final String CL_AGENT = "org/spongepowered/metronome/Agent";

        static final String MD_RUNTRANSFORMERS = "runTransformers";
        static final String MD_FINEST = "finest";
        static final String MD_TRANSFORM = "transform";
        
        static final String DESC_RUNTRANSFORMERS = "(Ljava/lang/String;Ljava/lang/String;[B)[B";
        static final String DESC_FINEST = "(Ljava/lang/String;[Ljava/lang/Object;)V";
        static final String DESC_STRING = "(Ljava/lang/String;)V";
        static final String DESC_OBJECT = "(Ljava/lang/Object;)V";

        /**
         * Method visitor which transforms bytecode in "runTransformers"
         */
        static class MV extends MethodVisitor {
            
            private int ordinal, local;
            private boolean captureNextStore;

            public MV(MethodVisitor mv) {
                super(Opcodes.ASM5, mv);
            }

            @Override
            public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
                if (Transformer.CL_LOGWRAPPER.equals(owner)
                        && Transformer.MD_FINEST.equals(name)
                        && Transformer.DESC_FINEST.equals(desc)) {
                    super.visitMethodInsn(opcode, owner, name, desc, itf);
                    if (this.ordinal > 0 && this.ordinal < 3) {
                        super.visitVarInsn(Opcodes.ALOAD, 6);
                        String method = this.ordinal == 1 ? "before" : "after";
                        super.visitMethodInsn(Opcodes.INVOKESTATIC, Transformer.CL_AGENT, method, Transformer.DESC_STRING, false);
                    }
                    this.ordinal++;
                } else if (this.local > 0
                        && this.ordinal > 3
                        && Transformer.CL_TRANSFORMER.equals(owner)
                        && Transformer.MD_TRANSFORM.equals(name)) {
                    super.visitVarInsn(Opcodes.ALOAD, this.local);
                    super.visitMethodInsn(Opcodes.INVOKESTATIC, Transformer.CL_AGENT, "before", Transformer.DESC_OBJECT, false);
                    super.visitMethodInsn(opcode, owner, name, desc, itf);
                    super.visitVarInsn(Opcodes.ALOAD, this.local);
                    super.visitMethodInsn(Opcodes.INVOKESTATIC, Transformer.CL_AGENT, "after", Transformer.DESC_OBJECT, false);
                } else {
                    super.visitMethodInsn(opcode, owner, name, desc, itf);
                }
            }
            
            @Override
            public void visitTypeInsn(int opcode, String type) {
                super.visitTypeInsn(opcode, type);
                if (opcode == Opcodes.CHECKCAST
                        && Transformer.CL_TRANSFORMER.equals(type)
                        && this.ordinal > 3) {
                    this.captureNextStore = true;
                }
            }
            
            @Override
            public void visitVarInsn(int opcode, int var) {
                super.visitVarInsn(opcode, var);
                if (this.captureNextStore && opcode == Opcodes.ASTORE) {
                    this.local = var;
                    this.captureNextStore = false;
                }
            }
        }
        
        /**
         * Class visitor which transforms methods in LaunchClassLoader
         */
        static class CV extends ClassVisitor {

            public CV(ClassVisitor cv) {
                super(Opcodes.ASM5, cv);
            }
            
            @Override
            public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, desc, signature, exceptions);
                if (Transformer.MD_RUNTRANSFORMERS.equals(name)
                        && Transformer.DESC_RUNTRANSFORMERS.equals(desc)) {
                    return new MV(mv);
                }
                return mv;
            }
            
        }

        @Override
        public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain,
                byte[] classfileBuffer) throws IllegalClassFormatException {
            if (Transformer.CL_CLASSLOADER.equals(className)) {
                return this.transformClassLoader(classfileBuffer);
            }
            return classfileBuffer;
        }

        private byte[] transformClassLoader(byte[] bytes) {
            ClassReader cr = new ClassReader(bytes);
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES);
            ClassVisitor cv = new CV(cw);
            cr.accept(cv, 0);
            return cw.toByteArray();
        }
    }
    
    /**
     * Mutable long, so we can easily store the times in a Map
     */
    static final class Time {
        long value;
        
        public Long asLong() {
            return Long.valueOf(this.value);
        }
    }
    
    /**
     * Current benchmark start time
     */
    private static long start;
    
    /**
     * All recorded times
     */
    private static Map<String, Time> times = new HashMap<String, Time>();
    
    private Agent() {
        // No instances
    }
    
    /**
     * Callback from injected code, begin benchmarking a specific transformer
     * 
     * @param name transformer name
     */
    public static void before(String name) {
        Agent.start = System.currentTimeMillis();
    }
    
    /**
     * Callback from injected code, end benchmarking a transformer
     * 
     * @param name transformer name
     */
    public static void after(String name) {
        long elapsed = System.currentTimeMillis() - start;
        Time time = Agent.times.get(name);
        if (time == null) {
            time = new Time();
            Agent.times.put(name, time);
        }
        time.value += elapsed;
    }
    
    /**
     * Callback from injected code, begin benchmarking a specific transformer
     * 
     * @param transformer transformer
     */
    public static void before(Object transformer) {
        Agent.before(transformer.getClass().getName());
    }
    
    /**
     * Callback from injected code, end benchmarking a transformer
     * 
     * @param transformer transformer
     */
    public static void after(Object transformer) {
        Agent.after(transformer.getClass().getName());
    }

    /**
     * Premain call
     * 
     * @param arg argument
     * @param instrumentation instrumentation instance
     */
    public static void premain(String arg, Instrumentation instrumentation) {
        instrumentation.addTransformer(new Transformer(), true);
    }
    
    /**
     * Method to obtain current time information
     * 
     * @return Times as key/value pairs with transformer class name as key and
     *      total time as value
     */
    public static Map<String, Long> getTimes() {
        Map<String, Long> times = new TreeMap<String, Long>();
        for (Entry<String, Time> entry : Agent.times.entrySet()) {
            times.put(entry.getKey(), entry.getValue().asLong());
        }
        return times;
    }

}
