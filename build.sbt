name := "auth-service"

organization := "codecraft"

version := "1.0.0-SNAPSHOT"

scalaVersion := "2.11.8"

enablePlugins(DockerPlugin)

resolvers ++= Seq(
  "Akka Snapshot Repository" at "http://repo.akka.io/snapshots/"
)

libraryDependencies ++= Seq(
  "io.github.nremond" %% "pbkdf2-scala" % "0.5",
  "com.typesafe.akka" %% "akka-actor" % "2.4.6",
  "org.scalatest" % "scalatest_2.11" % "2.2.6" % "test",
  "codecraft" %% "codegen" % "1.0.0-SNAPSHOT",
  "codecraft" %% "auth-messages" % "1.0.0-SNAPSHOT",
  "codecraft" %% "cloud" % "1.0.0-SNAPSHOT"
)

dockerfile in docker := {
	val jarFile: File = sbt.Keys.`package`.in(Compile, packageBin).value
  val classpath = (managedClasspath in Compile).value
  val mainclass = mainClass.in(Compile, packageBin).value.getOrElse(sys.error("Expected exactly one main class"))
  val jarTarget = s"/app/${jarFile.getName}"
  // Make a colon separated classpath with the JAR file
  val classpathString = classpath.files.map("/app/" + _.getName)
    .mkString(":") + ":" + jarTarget
  new Dockerfile {
    // Base image
    //from("alpine:3.2")
    from("anapsix/alpine-java")
    // Add all files on the classpath
    add(classpath.files, "/app/")
    // Add the JAR file
    add(jarFile, jarTarget)
    // On launch run Java with the classpath and the main class
    entryPoint("java", "-cp", classpathString, mainclass)
  }
}
