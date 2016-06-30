package codecraft.auth

import akka.actor.ActorSystem
import codecraft.auth._
import codecraft.platform.amqp.{AmqpCloud, RoutingInfo}
import codecraft.platform.ICloud
import codecraft.user._
import io.github.nremond.SecureHash
import scala.concurrent.duration._
import scala.util.{Try, Success, Failure}

final case class AuthRecord(
  passwordHash: String
)

case class AuthService(cloud: ICloud) extends IAuthService {
  // Maps from email to AuthRecord
  var auths = Map.empty[String, AuthRecord]
  // Maps from token to email
  var tokenToEmail = Map.empty[String, String]
  // Maps from email to token
  var emailToToken = Map.empty[String, String]

  def uuid = java.util.UUID.randomUUID.toString

  // Not thread safe.
  def invalidateEmailToken(email: String) = {
    emailToToken get email foreach { token =>
      tokenToEmail -= token
    }
    emailToToken -= email
  }

  def generateToken(email: String) = {
    val token = uuid
    emailToToken += (email -> token)
    tokenToEmail += (token -> email)
    token
  }

  def add(cmd: AddAuth): AddAuthReply = this.synchronized {
    auths.get(cmd.email) map { _ =>
      // Already exists.
      AddAuthReply(None, Some("Email already registered"))
    } getOrElse {
      val passwordHash = SecureHash.createHash(
        cmd.password
      )
      val record = AuthRecord(
        passwordHash
      )

      auths += (cmd.email -> record)

      val token = generateToken(cmd.email)

      AddAuthReply(Some(token), None)
    }
  }

  def get(cmd: GetAuth): GetAuthReply = this.synchronized {
    auths.get (cmd.email) map { auth =>
      invalidateEmailToken(cmd.email)
      val token = generateToken(cmd.email)

      GetAuthReply(Some(token), None)
    } getOrElse {
      GetAuthReply(None, Some("Auth does not exist"))
    }
  }

  def consume(cmd: ConsumeToken): ConsumeTokenReply = this.synchronized {
    tokenToEmail get (cmd.token) match {
      case None =>
        ConsumeTokenReply(None, Some("Token is invalid"))
      case Some(email) =>
        val token = generateToken(email)
        ConsumeTokenReply(Some(token), None)
    }
  }

  def onError(exn: Throwable) {
    println(s"$exn")
  }
}

object Main {
  val routingInfo = RoutingInfo(
    AuthRoutingGroup.cmdInfo.map {
      case registry => (registry.key, registry)
    } toMap,
    Map(
      AuthRoutingGroup.groupRouting.queueName -> AuthRoutingGroup.groupRouting
    )
  )

  def main(argv: Array[String]) {
    val system = ActorSystem("service")
    val cloud = AmqpCloud(
      system,
      List(
        "amqp://192.168.99.101:5672"
      ),
      routingInfo
    )

    val service = AuthService(cloud)

    import system.dispatcher

    cloud.subscribeCmd(
      "cmd.auth",
      service,
      5 seconds
    ) onComplete {
      case Failure(e) => throw e
      case Success(_) => println("Started service.")
    }
  }
}

