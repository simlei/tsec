logLevel := Level.Warn
addSbtPlugin("com.47deg"          % "sbt-microsites" % "0.7.16")
addSbtPlugin("org.tpolecat"       % "tut-plugin"     % "0.6.13")
addSbtPlugin("com.typesafe.sbt"   % "sbt-ghpages"    % "0.6.3")
addSbtPlugin("pl.project13.scala" % "sbt-jmh"        % "0.3.7")
addSbtPlugin("com.timushev.sbt"   % "sbt-updates"    % "0.3.3")
addSbtPlugin("com.github.gseitz"  % "sbt-release"    % "1.0.12")
addSbtPlugin("com.jsuereth"       % "sbt-pgp"        % "1.1.2")
addSbtPlugin("org.xerial.sbt"     % "sbt-sonatype"   % "2.6")
addSbtPlugin("com.eed3si9n" % "sbt-assembly" % "0.15.0")


libraryDependencies ++= List(
  "com.geirsson" %% "scalafmt-core" % "1.3.0",
  "com.geirsson" %% "scalafmt-cli"  % "1.3.0"
)

unmanagedJars in Compile ++= tsec.build.SunShine.`tools.jar`.toSeq

sources in Compile ++= {
  if (tsec.build.SunShine.canWeUseToolsDotJar_?)
    file("project/boiler/gensodium.scala").getAbsoluteFile :: Nil
  else Nil
}
